"""Evidence-based diagnostics and human/JSON output; no device operations."""

import json

from t7manager.cli import i18n


# === 5. Presentation and unified command-line interface ===
ERROR_MESSAGES = {
    "unsafe_local_record": "상태 파일의 링크·소유권·권한을 확인하세요. 자동으로 변경하지 않았습니다.",
    "unsafe_local_directory": "저장 디렉터리의 소유권·쓰기 권한이 안전 조건과 다릅니다. 기존 기록을 보존하고 확인하세요.",
    "invalid_language": "--lang에는 en 또는 ko를 지정하세요.",
    "invalid_arguments": "옵션을 해석할 수 없습니다. --help로 사용법을 확인하세요.",
    "explicit_command_required": "실행할 명령을 명시하세요. 예: t7 unlock --execute. 명령을 생략한 경우에는 dry-run만 가능합니다.",
    "interactive_terminal_required": "암호 숨김 입력을 위해 대화형 터미널에서 실행하세요.",
    "specify_serial_from_list": "장치가 여러 개입니다. list에서 확인한 일련번호를 --serial로 지정하세요.",
    "device_in_use_unmount_or_stop_disk_work_first": "장치가 사용 중입니다. 파일 작업을 끝내고 정상 언마운트하세요.",
    "execute_requires_sudo": "장치 명령 실행에는 관리자 권한이 필요합니다. sudo로 실행하세요.",
    "sg_raw_required": "sg_raw를 찾지 못했습니다. sg3_utils 설치 여부를 확인하세요.",
    "transport_failed_no_retry": "장치 명령이 실패했습니다. 반환 코드와 sense 정보를 검토하세요. 자동 재시도하지 않습니다.",
    "transport_timeout_no_retry": "장치 응답 대기 시간이 초과됐습니다. 결과를 검토하고 반복 실행하지 마세요.",
    "device_identity_or_generation_changed": "조회 중 장치 식별 정보가 변경됐습니다.",
    "matching_T7_not_found": "일치하는 장치를 찾지 못했습니다. 연결 상태와 일련번호를 확인하세요.",
    "unsupported_discovery_length_convention": "Discovery 길이 형식을 해석할 수 없습니다. 원본 응답 검토가 필요합니다.",
    "authentication_rejected": "현재 비밀번호 인증이 거부됐습니다. 변경 명령은 진행하지 않았습니다.",
    "new_password_same_no_changes": "현재 암호 입력과 새 암호 입력이 같습니다. 변경하지 않았습니다.",
    "unsupported_password_format_no_auth_sent": "암호는 공백 없는 ASCII 4~16자여야 합니다. 인증을 전송하지 않았습니다.",
    "password_entries_differ_no_auth_sent": "새 암호 두 입력이 다릅니다. 인증을 전송하지 않았습니다.",
    "interrupted": "사용자가 실행을 중단했습니다. 변경 여부와 복구 필요 상태를 확인하세요.",
    "security_mode_precondition_failed": "보안 상태가 작업 조건과 다릅니다. 설정은 보안 비활성, 제거는 보안 활성·잠금 해제 상태여야 합니다.",
    "local_error": "로컬 검사 또는 파일 처리에 실패했습니다. 권한과 경로를 확인하세요. 원인은 확정되지 않았습니다.",
}


# Presentation is derived from evidence; it must not initiate device traffic or
# infer Samsung password security from Discovery's LockingEnabled flag alone.
def diagnostic_summary(result):
    action = result.get("action")
    error = result.get("error")
    read_only_action = action in ("list", "status", "probe", "probe-default-credential")
    host_stage = result.get("error_stage") in (
        "옵션 해석", "장치 선택", "로그 저장 위치 검사", "장치 사용 여부 검사",
        "실행 환경 검사", "동시 실행 검사",
    ) or result.get("error_stage") in tuple(i18n.EN_MESSAGES[k] for k in (
        "옵션 해석", "장치 선택", "로그 저장 위치 검사", "장치 사용 여부 검사", "실행 환경 검사", "동시 실행 검사"
    ))
    if result.get("dry_run") or read_only_action or host_stage:
        changes = "none"
    elif result.get("changes_may_have_occurred") is True:
        changes = "possible"
    elif result.get("changes_may_have_occurred") is False:
        changes = "none"
    else:
        changes = "unknown"

    # Session traffic can be uncertain even when no data/policy Set was sent.
    uncertain = (
        result.get("recovery_required") is True
        or result.get("session_may_be_open") is True
        or result.get("transaction_may_be_open") is True
    )
    # Use the engine's completed cleanup evidence, not the error code alone.
    # This affects reporting only; it cannot authorize a device operation.
    rejection_resolved = (
        action == "unlock"
        and error == "authentication_rejected"
        and result.get("retry_without_reconnection") is True
        and result.get("session_may_be_open") is False
        and result.get("transaction_may_be_open") is False
        and result.get("changes_may_have_occurred") is False
    )
    if not error and not result.get("result_save_error"):
        next_code = "execute_after_review" if result.get("dry_run") else "none"
        message = "계획과 조건을 확인한 뒤 --execute로 실행하세요." if result.get("dry_run") else "추가 조치가 필요하지 않습니다."
    elif uncertain or (error and changes in ("possible", "unknown")):
        next_code = "review_required"
        message = "작업 로그와 현재 상태를 검토한 뒤 다음 작업을 결정하세요. 불확실한 변경 명령은 자동 재시도하지 않습니다."
    elif error == "explicit_command_required":
        next_code = "specify_command"
        message = "unlock, status, probe 등의 명령을 명시해 다시 실행하세요. 장치 명령은 전송되지 않았습니다."
    elif error == "authentication_rejected":
        next_code = "correct_password_new_run"
        message = "현재 암호를 확인하고 새 실행으로 다시 시도할 수 있습니다."
    elif error in ("unsupported_password_format_no_auth_sent", "password_entries_differ_no_auth_sent", "new_password_same_no_changes"):
        next_code = "correct_input"
        message = "입력을 수정해 다시 실행하세요. 인증은 전송하지 않았습니다."
    elif error == "device_in_use_unmount_or_stop_disk_work_first":
        next_code = "unmount_normally"
        message = "파일 작업을 끝내고 대상 파티션을 정상 언마운트한 뒤 실행하세요."
    elif result.get("result_save_error") and not error:
        next_code = "preserve_console_result"
        message = "화면 결과를 보존하고 저장 위치를 점검하세요. 저장 실패만으로 장치 작업을 반복하지 마세요."
    elif error in ("interrupted", "interrupted_no_retry") and changes == "none":
        next_code = "new_run_after_checks"
        message = "작업 로그와 현재 장치 상태를 확인한 뒤 새 실행을 시작하세요."
    else:
        next_code = "check_error"
        message = "오류 원인과 실행 조건을 확인하세요. 장치 통신 오류라면 반복 실행 전에 결과를 검토하세요."
    return {
        "failure_stage": result.get("error_stage") if error else result.get("result_save_error_stage") if result.get("result_save_error") else None,
        "cause": error or result.get("result_save_error"),
        "changes_this_run": changes,
        "prior_changes_possible": False,
        "recovery": "required" if uncertain else "not_assessed" if result.get("dry_run") or host_stage or action in ("status", "probe", "list") else "not_required" if rejection_resolved or result.get("recovery_required") is False or (not error and result.get("complete")) else "unknown",
        "next_action": next_code,
        "next_action_message": i18n.tr(message),
    }


def display_diagnostic(result, as_json):
    if as_json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return
    if result.get("action") == "list" and not result.get("error"):
        candidates = result.get("candidates", [])
        if not candidates:
            print(i18n.tr("T7 후보 장치가 없습니다."))
        for info in candidates:
            print(i18n.tr("장치: ") + f"{info['model']} ({info['device']})")
            print(i18n.tr("일련번호: ") + ", ".join(info["serials"]))
        print(i18n.tr("호스트 목록 조회 완료 · 장치 명령 전송 없음"))
        return
    info = result.get("identity", {})
    if result.get("model_warning"):
        print(result["model_warning"])
    if info:
        print(i18n.tr("장치: ") + f"{info.get('model', '?')} ({info.get('device', '?')})")
        print(i18n.tr("일련번호: ") + ", ".join(info.get("serials", [])))
    if result.get("dry_run"):
        print(i18n.tr("실행 계획만 확인했습니다. 실제 잠금 상태는 조회하지 않았습니다."))
        if result.get("plan"):
            print(i18n.tr("계획: ") + result["plan"])
    state = result.get("after") or result.get("discovery") or result.get("before")
    if state:
        print(i18n.tr("잠금 상태: ") + (i18n.tr("잠김") if state["locked"] else i18n.tr("잠금 해제됨")) + i18n.tr(" (마지막 관측)"))
        security = result.get("password_security")
        print(i18n.tr("비밀번호 보안: ") + ({"enabled": i18n.tr("활성"), "disabled": i18n.tr("비활성")}.get(security, i18n.tr("이 조회만으로 확정하지 않음"))))
        if security not in ("enabled", "disabled"):
            print("TCG LockingEnabled: " + str(state["locking_enabled"]))
    if result.get("action") == "probe":
        if "inquiry" in result:
            print(i18n.tr("장치 revision: ") + result["inquiry"]["revision"])
        if state:
            print(f"ComID: 0x{state['comid']:04X}")
        if result.get("classification"):
            labels = {
                "observed_profile_match_unverified_device": i18n.tr("기존 응답 형식과 일치 (unlock 호환성 입증 아님)"),
                "parsed_profile_differs": i18n.tr("현재 unlock 조건과 다른 응답"),
                "unsupported_or_incomplete": i18n.tr("미지원 형식 또는 수집 미완료"),
            }
            print(i18n.tr("응답 비교: ") + i18n.tr(labels.get(result["classification"], result["classification"])))
    summary = result.get("diagnostic") or diagnostic_summary(result)
    if result.get("error"):
        error = result["error"]
        print(i18n.tr("실행 중단 — ") + (summary["failure_stage"] or i18n.tr("확인 불가")))
        print(i18n.tr(ERROR_MESSAGES.get(error, i18n.tr("확인된 오류: ") + error)))
        print(i18n.tr("오류 코드: ") + error)
        for mount in result.get("usage", {}).get("mounts", []):
            print(i18n.tr("마운트: ") + f"{mount.get('device', mount.get('device_number', '?'))} → {mount['mountpoint']}")
        for command in result.get("commands", [])[-1:]:
            if command.get("returncode"):
                print(i18n.tr("명령 반환 코드: ") + str(command["returncode"]))
        if result.get("auth_method_status"):
            print(i18n.tr("인증 응답 status: ") + str(result["auth_method_status"]))
    elif result.get("complete"):
        outcomes = {
            "already_unlocked": i18n.tr("이미 잠금 해제 상태입니다."),
            "unlocked": i18n.tr("잠금 해제 완료"),
            "password_changed": i18n.tr("암호 변경 및 새 암호 인증 완료"),
            "password_verified": i18n.tr("후보 암호의 두 credential 검증 완료"),
            "password_set": i18n.tr("암호 설정 완료"),
            "password_removed": i18n.tr("비밀번호 보안 제거 완료"),
            "password_removal_verified": i18n.tr("암호 제거 결과 검증 완료"),
            "credential_structure_verified": i18n.tr("기본 credential 구조 조회 완료 (값 저장 없음)"),
        }
        print(outcomes.get(result.get("outcome"), i18n.tr("조회 완료")))
    elif result.get("dry_run"):
        print(i18n.tr("호스트 준비 상태: 통과 (장치 상태 검증은 실행 시 수행)"))
    if result.get("error") or result.get("result_save_error"):
        print(i18n.tr("이번 실행의 설정 변경: ") + {"none": i18n.tr("없음"), "possible": i18n.tr("발생했을 수 있음"), "unknown": i18n.tr("확인 불가")}[summary["changes_this_run"]])
        if summary["prior_changes_possible"]:
            print(i18n.tr("이전 작업의 변경 가능성: 있음 (검증 전용 실행이 이어받은 기록)"))
        print(i18n.tr("다음 조치: ") + summary["next_action_message"])
    if result.get("result_save_error"):
        print(i18n.tr("결과 저장 오류: 화면 결과를 보존하세요. 파일은 최신 상태가 아닐 수 있습니다."))
    elif result.get("result_path"):
        print(i18n.tr("결과 파일: ") + result["result_path"])
    elif not result.get("dry_run"):
        print(i18n.tr("상세 결과 파일 저장 안 함 (--save-results로 저장 가능; 작업 로그는 별도)"))
    if result.get("log_path"):
        print(i18n.tr("작업 로그: ") + result["log_path"])
