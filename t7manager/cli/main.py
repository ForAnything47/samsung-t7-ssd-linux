"""CLI argument parsing and dispatch to common operation implementations."""

import argparse
from datetime import datetime, timezone
import os
import resource
import shutil
import sys
import uuid

from t7manager import device as device_api, errors, paths, records, safety, transport
from t7manager.cli import i18n, output
from t7manager.operations import password as password_ops, probe as probe_ops, security as security_ops, unlock as unlock_ops


ACTION_PLANS = {
    "unlock": "Discovery → 현재 암호 1회 → 익명 상태·인증·잠금 해제 → Relink → 상태 확인",
    "status": "Discovery로 잠금 상태 조회 (비밀번호 보안 여부 단독 확정 불가)",
    "probe": "INQUIRY·Discovery 조회 및 프로파일 비교 (unlock 호환성 검증 아님)",
    "probe-default-credential": "익명 AdminSP → 기본 credential 구조 조회 → 종료·상태 확인 (값 저장 없음)",
    "change-password": "보안 활성·잠금 해제 확인 → 현재 암호 1회·새 암호 2회 → 변경·커밋 → 새 암호 인증",
    "set-password": "비활성 보안 모드 확인 → 새 암호 2회 → 기본 credential 인증·설정·커밋 → 두 인증·모드·상태 확인",
    "remove-password": "보안 활성·잠금 해제 확인 → 현재 암호 1회 → 제거·커밋 → 두 기본 credential 인증·모드·상태 확인",
}


def list_cli(argv):
    """Host-only list with explicit options; never silently drop arguments."""
    class Parser(argparse.ArgumentParser):
        def error(self, message):
            raise errors.Stop("invalid_arguments")
    parser = Parser(description=i18n.tr("T7 계열 후보를 호스트에서 조회합니다. 장치 명령은 전송하지 않습니다."))
    parser.add_argument("--lang", choices=("en", "ko"), help=i18n.tr("언어 선택 (기본: 시스템 로캘)"))
    parser.add_argument("--serial", help=i18n.tr("일련번호로 목록 필터"))
    parser.add_argument("--json", action="store_true", help=i18n.tr("요약 대신 JSON 하나 출력"))
    report = {"action": "list", "complete": False, "commands": [], "dry_run": False,
              "save_results": False, "result_path": None, "device_commands_sent": False}
    as_json = "--json" in argv
    try:
        args = parser.parse_args(argv)
        candidates = device_api.list_devices(family=True)
        report["candidates"] = [info for info in candidates if args.serial in info["serials"]] if args.serial else candidates
        report["complete"] = True
    except errors.Stop as exc:
        report.update(error=str(exc), error_stage="옵션 해석")
    except KeyboardInterrupt:
        report.update(error="interrupted", error_stage="장치 선택")
    except Exception:
        report.update(error="local_error", error_stage="장치 선택")
    report["diagnostic"] = output.diagnostic_summary(report)
    report = i18n.localized_report(report)
    output.display_diagnostic(report, as_json)
    return 0 if report["complete"] else 1


# Dry-run performs host checks only. It neither proves device security state
# nor changes the device. Device commands create a mandatory operation log.
def diagnostic_cli(action, argv, *, host_adapter=None):
    class Parser(argparse.ArgumentParser):
        def error(self, message):
            raise errors.Stop("invalid_arguments")

    parser = Parser(
        description=i18n.tr("기본 출력은 요약입니다. --json: JSON 출력, --execute: 선택한 장치 작업 실행.")
    )
    parser.add_argument("--lang", choices=("en", "ko"), help=i18n.tr("언어 선택 (기본: 시스템 로캘)"))
    parser.add_argument("--allow-unverified-model", action="store_true",
                        help=i18n.tr("T7/T7 Touch 미검증 작업 허용; 후보가 한 대면 자동 선택. 안전 검사는 유지됩니다."))
    parser.add_argument("--serial", help=i18n.tr("일련번호로 대상 장치 선택"))
    parser.add_argument("--execute", action="store_true", help=i18n.tr("실제 장치 작업 실행; 생략하면 dry-run"))
    parser.add_argument("--json", action="store_true", help=i18n.tr("요약 대신 stdout에 JSON 하나 출력"))
    parser.add_argument(
        "--save-results",
        action="store_true",
        help=i18n.tr("상세 결과 JSON 저장; 필수 작업 로그는 이 옵션과 별개"),
    )
    result = {"action": action, "complete": False, "commands": [], "dry_run": "--execute" not in argv, "save_results": "--save-results" in argv, "result_path": None}
    stage = "옵션 해석"
    out = None
    as_json = "--json" in argv
    try:
        args = parser.parse_args(argv)
        as_json = args.json
        result["dry_run"] = not args.execute
        result["save_results"] = args.save_results
        stage = "장치 선택"
        candidates = device_api.list_devices(family=action == "probe" or args.allow_unverified_model)
        selected = (
            [i for i in candidates if args.serial in i["serials"]]
            if args.serial
            else candidates
        )
        if len(selected) != 1:
            result["candidates"] = candidates
            raise errors.Stop(
                "matching_T7_not_found" if not selected else "specify_serial_from_list"
            )
        info = selected[0]
        result["identity"] = info
        if not (device_api.is_supported_model(info["model"]) or
                ((action == "probe" or args.allow_unverified_model) and device_api.is_t7_family(info["model"]))):
            raise errors.Stop("unsupported_security_profile")
        result["allow_unverified_model"] = args.allow_unverified_model
        result["unverified_model"] = not device_api.is_supported_model(info["model"])
        if result["unverified_model"]:
            result["model_warning"] = i18n.tr("미검증 모델: 호환성과 데이터 안전성은 확인되지 않았습니다.")
        host = transport.UnverifiedModelHost() if args.allow_unverified_model else transport.Host()
        if host_adapter is not None:
            host = host_adapter(host)
        host_options = {"host": host} if args.allow_unverified_model or host_adapter is not None else {}
        if not info["serials"]:
            raise errors.Stop("device_serial_unavailable")
        state = records.state_for_identity(info)
        runroot = paths.data_root() / ("compatibility-runs" if action == "probe" else "runs")
        stage = "로그 저장 위치 검사"
        for path in ((paths.BASE, state, runroot) if args.save_results else (paths.BASE, state)):
            safety.local_output(path, info)
        stage = "장치 사용 여부 검사"
        result["usage"] = safety.usage_snapshot(info["device"])
        candidate = (
            safety.auto_unmount_candidate(result["usage"]) if action == "unlock" else None
        )
        result["host_checks_passed"] = result["usage"]["idle"] or candidate is not None
        if action == "unlock":
            result["planned_unmount"] = candidate
            result["automatic_unmount"] = True
        if not result["host_checks_passed"]:
            raise errors.Stop("device_in_use_unmount_or_stop_disk_work_first")
        if args.execute:
            stage = "실행 환경 검사"
            if os.geteuid() != 0:
                raise errors.Stop("execute_requires_sudo")
            if not shutil.which("sg_raw"):
                raise errors.Stop("sg_raw_required")
            os.umask(0o077)
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            stage = "동시 실행 검사"
            with records.run_lock(state):
                if args.save_results:
                    records.ensure_result_root(runroot)
                out = (
                    runroot
                    / (
                        datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
                        + "-"
                        + uuid.uuid4().hex[:8]
                    )
                    if args.save_results
                    else None
                )
                stage = "장치 조회"
                if action == "probe":
                    collected = probe_ops.collect(info, out, state=state)
                elif action == "probe-default-credential":
                    collected = probe_ops.probe_default_credential(
                        info, args.serial or info["serials"][0], out, state, **host_options
                    )
                elif action in ("set-password", "remove-password"):
                    collected = security_ops.execute_security_setup(
                        action, info, args.serial or info["serials"][0], out, state, **host_options
                    )
                elif action == "change-password":
                    collected = password_ops.execute_password_change(
                        info,
                        args.serial or info["serials"][0],
                        out,
                        state,
                        **host_options,
                    )
                else:
                    collected = unlock_ops.execute_unlock(
                        info, args.serial or info["serials"][0], action, out, state, **host_options
                    )
                result.update(collected)
                result["action"] = action
                if not result["complete"]:
                    last = result.get("commands", [])[-1:]
                    if result.get("error") in (
                        "unsupported_password_format_no_auth_sent",
                        "password_entries_differ_no_auth_sent",
                        "new_password_same_no_changes",
                    ):
                        result["error_stage"] = "password input"
                    result["error_stage"] = result.get("error_stage") or (
                        last[0]["name"] + " (전송 또는 응답 검증)" if last else stage
                    )
        else:
            result["planned_queries"] = (
                ["INQUIRY", "Discovery"] if action == "probe" else ["Discovery"]
            )
            result["plan"] = ACTION_PLANS[action]
            if action in ("set-password", "remove-password", "change-password"):
                result["experimental"] = True
    except errors.Stop as e:
        result.update(error=str(e), error_stage=stage)
    except KeyboardInterrupt:
        result.update(error="interrupted", error_stage=stage)
    except Exception:
        result.update(error="local_error", error_stage=stage, complete=False)
    if out is not None and out.exists():
        result["result_path"] = str(out / "result.json")
    result["diagnostic"] = output.diagnostic_summary(result)
    result = i18n.localized_report(result)
    if result["result_path"] is not None:
        try:
            records.save(out / "result.json", result)
        except (Exception, KeyboardInterrupt):
            # Preserve an already observed device outcome, error and stage.
            # The process exit code still reports unsuccessful report delivery.
            result["result_save_error"] = "result_save_failed"
            result["result_save_error_stage"] = "결과 파일 저장"
    result["diagnostic"] = output.diagnostic_summary(result)
    result = i18n.localized_report(result)
    output.display_diagnostic(result, as_json)
    return (
        1
        if result.get("error") or result.get("result_save_error") or (not result.get("dry_run") and not result["complete"])
        else 0
    )


# ---- Unified command line ----
def _main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0] in ("lock", "relock"):
        print(
            i18n.tr("Direct relock is quarantined. Unmount and safely disconnect the SSD."),
            file=sys.stderr,
        )
        return 1
    if args and args[0] in (
        "status",
        "probe",
        "unlock",
        "change-password",
        "probe-default-credential",
        "set-password",
        "remove-password",
    ):
        return diagnostic_cli(args[0], args[1:])
    if args and args[0] == "list":
        return list_cli(args[1:])
    if args in (["--help"], ["-h"]):
        print(i18n.help_text())
        return 0
    if args and args[0] == "--list":
        return list_cli(args[1:])
    if "--execute" in args:
        # An omitted command means unlock only for a host-only preview.
        # Never infer a device operation from a flag alone.
        report = {"action": "cli", "complete": False, "commands": [],
                  "dry_run": False, "save_results": False, "result_path": None,
                  "device_commands_sent": False, "changes_may_have_occurred": False,
                  "error": "explicit_command_required", "error_stage": "옵션 해석"}
        report["diagnostic"] = output.diagnostic_summary(report)
        output.display_diagnostic(i18n.localized_report(report), "--json" in args)
        return 1
    return diagnostic_cli("unlock", args)


def main(argv=None):
    """Select language before parsing/help/prompts, and restore library context."""
    # Language context lives in the i18n module.
    previous = i18n.LANGUAGE
    args = list(sys.argv[1:] if argv is None else argv)
    i18n.LANGUAGE = i18n.locale_language()
    clean = []
    try:
        index = 0
        while index < len(args):
            token = args[index]
            if token == "--lang" or token.startswith("--lang="):
                if token == "--lang":
                    index += 1
                    value = args[index] if index < len(args) else None
                else:
                    value = token.split("=", 1)[1]
                if value not in ("en", "ko"):
                    report = {"action": "cli", "complete": False, "commands": [],
                              "error": "invalid_language", "error_stage": "옵션 해석",
                              "dry_run": "--execute" not in args, "result_path": None}
                    report["diagnostic"] = output.diagnostic_summary(report)
                    output.display_diagnostic(i18n.localized_report(report), "--json" in args)
                    return 1
                i18n.LANGUAGE = value
            else:
                clean.append(token)
            index += 1
        return _main(clean)
    finally:
        i18n.LANGUAGE = previous
