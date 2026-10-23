"""CLI message catalog and display-field localization."""

import os


# Exact message lookup keeps device data, paths and machine error codes intact.
# Library callers retain Korean defaults; main selects a language per invocation.
LANGUAGE = "ko"


EN_MESSAGES = {
    "T7/T7 Touch 미검증 작업 허용; 후보가 한 대면 자동 선택. 안전 검사는 유지됩니다.": "Allow unverified T7/T7 Touch operations; select automatically when exactly one candidate exists. Safety checks remain enabled.",
    "미검증 모델: 호환성과 데이터 안전성은 확인되지 않았습니다.": "Unverified model: compatibility and data safety have not been established.",
    "상태 파일의 링크·소유권·권한을 확인하세요. 자동으로 변경하지 않았습니다.": "Check record links, ownership and permissions. They were not changed automatically.",
    "저장 디렉터리의 소유권·쓰기 권한이 안전 조건과 다릅니다. 기존 기록을 보존하고 확인하세요.": "Storage directory ownership or write permissions are unsafe. Preserve existing records and inspect the directory.","--lang에는 en 또는 ko를 지정하세요.": "Use en or ko with --lang.",
    "옵션을 해석할 수 없습니다. --help로 사용법을 확인하세요.": "Invalid arguments. Use --help to check the syntax.",
    "실행할 명령을 명시하세요. 예: t7 unlock --execute. 명령을 생략한 경우에는 dry-run만 가능합니다.": "Specify a command to execute, for example: t7 unlock --execute. An omitted command supports dry-run only.",
    "unlock, status, probe 등의 명령을 명시해 다시 실행하세요. 장치 명령은 전송되지 않았습니다.": "Run again with an explicit command such as unlock, status or probe. No SSD command was sent.",
    "암호 숨김 입력을 위해 대화형 터미널에서 실행하세요.": "Use an interactive terminal for hidden password input.",
    "장치가 여러 개입니다. list에서 확인한 일련번호를 --serial로 지정하세요.": "Multiple devices found. Select a serial from list using --serial.",' (마지막 관측)': ' (last observed)',
 ' (전송 또는 응답 검증)': ' (transport or response validation)',
 'Discovery → 현재 암호 1회 → 익명 상태·인증·잠금 해제 → Relink → 상태 확인': 'Discovery → current password once → '
                                                           'anonymous status/authentication/unlock '
                                                           '→ Relink → state verification',
 'Discovery 길이 형식을 해석할 수 없습니다. 원본 응답 검토가 필요합니다.': 'Unsupported Discovery length convention. Review '
                                                  'the response.',
 'Discovery로 잠금 상태 조회 (비밀번호 보안 여부 단독 확정 불가)': 'Query lock state using Discovery (cannot establish '
                                              'password security alone)',
 'INQUIRY·Discovery 조회 및 프로파일 비교 (unlock 호환성 검증 아님)': 'Query INQUIRY/Discovery and compare '
                                                      'profiles (does not prove unlock '
                                                      'compatibility)',
 'T7 계열 후보를 호스트에서 조회합니다. 장치 명령은 전송하지 않습니다.': 'List T7 family candidates from the host without '
                                             'device commands.',
 'T7 후보 장치가 없습니다.': 'No T7 candidate devices found.',
 'sg_raw를 찾지 못했습니다. sg3_utils 설치 여부를 확인하세요.': 'sg_raw was not found. Check your sg3_utils '
                                              'installation.',
 '검증 전용 실행': 'Verification only',
 '결과 JSON 저장; probe만 INQUIRY/Discovery 원본도 저장. 안전 기록은 이 옵션과 별개': 'Save result JSON; probe also '
                                                                 'saves raw INQUIRY/Discovery. '
                                                                 'Safety records are independent.',
 '결과 저장 오류: 화면 결과를 보존하세요. 파일은 최신 상태가 아닐 수 있습니다.': 'Result saving failed: preserve the console '
                                                  'output. The file may be stale.',
 '결과 파일 저장': 'Result file saving',
 '결과 파일 저장 안 함 (--save-results로 저장 가능; 안전 기록은 별도)': 'Result file not saved (use --save-results; '
                                                    'safety records are separate)',
 '결과 파일: ': 'Result file: ',
 '계획: ': 'Plan: ',
 '계획과 조건을 확인한 뒤 --execute로 실행하세요.': 'Review the plan and preconditions, then use --execute.',
 '기본 credential 구조 조회 완료 (값 저장 없음)': 'Default credential structure queried (value not saved)',
 '기본 출력은 요약입니다. --json: JSON 출력, --execute: 선택한 장치 작업 실행.': 'Default output is a summary. --json: '
                                                            'JSON output; --execute: run the '
                                                            'selected device operation.',
 '기존 암호 변경 pending·재연결 검사 → 후보 암호 1회 → 두 authority 인증·상태 검사 → 증거 보관·pending 해소 (Set 없음)': 'Check '
                                                                                          'password-change '
                                                                                          'pending/reconnection '
                                                                                          '→ '
                                                                                          'candidate '
                                                                                          'password '
                                                                                          'once → '
                                                                                          'authenticate '
                                                                                          'both '
                                                                                          'authorities/check '
                                                                                          'state → '
                                                                                          'archive '
                                                                                          'evidence/resolve '
                                                                                          'pending '
                                                                                          '(no '
                                                                                          'Set)',
 '기존 응답 형식과 일치 (unlock 호환성 입증 아님)': 'Matches observed profile (does not prove unlock '
                                    'compatibility)',
 '다음 조치: ': 'Next action: ',
 '동시 실행 검사': 'Concurrent execution check',
 '로그 저장 위치 검사': 'Local storage location check',
 '로컬 검사 또는 파일 처리에 실패했습니다. 권한과 경로를 확인하세요. 원인은 확정되지 않았습니다.': 'Local checks or file handling failed. '
                                                           'Check permissions and paths; the cause '
                                                           'is not established.',
 '마운트: ': 'Mount: ',
 '명령 반환 코드: ': 'Command return code: ',
 '미지원 형식 또는 수집 미완료': 'Unsupported format or incomplete collection',
 '미해결 세션·pending이 없는지 확인한 뒤 새 실행을 시작하세요.': 'Check for unresolved sessions or pending records '
                                           'before starting a new run.',
 '발생했을 수 있음': 'Possible',
 '변경 명령을 반복하거나 pending을 삭제하지 말고 기록과 상태를 검토하세요.': 'Review records and state. Do not repeat '
                                                 'mutations or delete pending records.',
 '보안 상태가 작업 조건과 다릅니다. 설정은 보안 비활성, 제거는 보안 활성·잠금 해제 상태여야 합니다.': 'Security preconditions do not '
                                                              'match. Setting requires disabled '
                                                              'security; removal requires enabled '
                                                              'security and an unlocked device.',
 '보안 활성·잠금 해제 확인 → 현재 암호 1회 → 제거·커밋 → 두 기본 credential 인증·모드·상태 확인': 'Check enabled '
                                                                    'security/unlocked state → '
                                                                    'current password once → '
                                                                    'remove/commit → verify both '
                                                                    'default '
                                                                    'credentials/mode/state',
 '보안 활성·잠금 해제 확인 → 현재 암호 1회·새 암호 2회 → 변경·커밋 → 새 암호 인증': 'Check enabled security/unlocked state → '
                                                        'current password once/new password twice '
                                                        '→ change/commit → authenticate new '
                                                        'password',
 '비밀번호 보안 제거 완료': 'Password security removed',
 '비밀번호 보안: ': 'Password security: ',
 '비활성': 'Disabled',
 '비활성 보안 모드 확인 → 새 암호 2회 → 기본 credential 인증·설정·커밋 → 두 인증·모드·상태 확인': 'Check disabled security mode '
                                                                    '→ new password twice → '
                                                                    'default credential '
                                                                    'authentication/set/commit → '
                                                                    'verify both '
                                                                    'credentials/mode/state',
 '사용자가 실행을 중단했습니다. 변경 여부와 복구 필요 상태를 확인하세요.': 'Execution interrupted. Check possible changes and '
                                             'recovery requirements.',
 '새 암호 두 입력이 다릅니다. 인증을 전송하지 않았습니다.': 'The two new password entries differ. No authentication was '
                                     'sent.',
 '실제 장치 작업 실행; 생략하면 dry-run': 'Execute the device operation; omit for dry-run',
 '실패 기록 검사: ': 'Failure record check: ',
 '실행 계획만 확인했습니다. 실제 잠금 상태는 조회하지 않았습니다.': 'Plan only. The actual device lock state was not queried.',
 '실행 중단 — ': 'Stopped — ',
 '실행 환경 검사': 'Execution environment check',
 '암호 변경 및 새 암호 인증 완료': 'Password changed and new password authenticated',
 '암호 설정 완료': 'Password set',
 '암호 제거 결과 검증 완료': 'Password removal verified',
 '암호는 공백 없는 ASCII 4~16자여야 합니다. 인증을 전송하지 않았습니다.': 'Password must contain 4–16 non-space ASCII '
                                                 'characters. No authentication was sent.',
 '없음': 'None',
 '오류 원인과 실행 조건을 확인하세요. 장치 통신 오류라면 반복 실행 전에 결과를 검토하세요.': 'Check the error and preconditions. Review '
                                                        'device communication failures before '
                                                        'another run.',
 '오류 코드: ': 'Error code: ',
 '옵션 해석': 'Argument parsing',
 '요약 대신 JSON 하나 출력': 'Output one JSON object instead of a summary',
 '요약 대신 stdout에 JSON 하나 출력': 'Output one JSON object to stdout instead of a summary',
 '응답 비교: ': 'Profile comparison: ',
 '이 조회만으로 확정하지 않음': 'Not established by this query alone',
 '이미 잠금 해제 상태입니다.': 'Already unlocked.',
 '이번 실행의 설정 변경: ': 'Settings changes in this run: ',
 '이전 실패 기록이 있어 중단했습니다. 상태 조회와 기록 검토가 필요하며 pending을 삭제해 우회하지 마세요.': 'An unresolved previous attempt '
                                                                   'blocks execution. Review state '
                                                                   'and records; do not bypass it '
                                                                   'by deleting pending.',
 '이전 인증 거부 기록을 검증 후 보관했습니다.': 'Previous authentication rejection verified and archived.',
 '이전 작업의 변경 가능성: 있음 (검증 전용 실행이 이어받은 기록)': 'Prior changes possible: yes (record inherited by '
                                          'verification-only run)',
 '이전 작업의 불확실한 결과를 검토해야 합니다. pending을 삭제하거나 변경 명령을 반복하지 마세요.': 'Review the uncertain previous '
                                                              'outcome. Do not delete pending or '
                                                              'repeat mutations.',
 '익명 AdminSP → 기본 credential 구조 조회 → 종료·상태 확인 (값 저장 없음)': 'Anonymous AdminSP → query default '
                                                          'credential structure → end/check state '
                                                          '(value not saved)',
 '인증 응답 status: ': 'Authentication response status: ',
 '인증이 거부됐습니다. 이번 실행에서는 재시도하지 않습니다. 같은 부팅에서 안전하게 전원을 차단·재연결한 뒤 새 unlock 실행으로 복구 조건을 확인할 수 있습니다.': 'Authentication '
                                                                                                 'was '
                                                                                                 'rejected; '
                                                                                                 'no '
                                                                                                 'retry '
                                                                                                 'in '
                                                                                                 'this '
                                                                                                 'run. '
                                                                                                 'After '
                                                                                                 'a '
                                                                                                 'safe '
                                                                                                 'power '
                                                                                                 'cycle '
                                                                                                 'within '
                                                                                                 'the '
                                                                                                 'same '
                                                                                                 'boot, '
                                                                                                 'a '
                                                                                                 'new '
                                                                                                 'unlock '
                                                                                                 'run '
                                                                                                 'can '
                                                                                                 'check '
                                                                                                 'recovery '
                                                                                                 'eligibility.',
 '일련번호: ': 'Serial: ',
 '일련번호로 대상 장치 선택': 'Select the device by serial',
 '일련번호로 목록 필터': 'Filter the list by serial',
 '일련번호로 장치 선택': 'Select by serial',
 '일치하는 장치를 찾지 못했습니다. 연결 상태와 일련번호를 확인하세요.': 'No matching device found. Check the connection and '
                                           'serial.',
 '입력을 수정해 다시 실행하세요. 인증은 전송하지 않았습니다.': 'Correct the input and start a new run. No authentication '
                                      'was sent.',
 '잠금 상태: ': 'Lock state: ',
 '잠금 해제 완료': 'Unlock complete',
 '잠금 해제됨': 'Unlocked',
 '잠김': 'Locked',
 '장치 revision: ': 'Device revision: ',
 '장치 명령 실행에는 관리자 권한이 필요합니다. sudo로 실행하세요.': 'Device commands require administrator privileges. Use '
                                           'sudo.',
 '장치 명령이 실패했습니다. 반환 코드와 sense 정보를 검토하세요. 자동 재시도하지 않습니다.': 'Device command failed. Review the '
                                                          'return code and sense information. No '
                                                          'automatic retry.',
 '장치 사용 여부 검사': 'Device usage check',
 '장치 선택': 'Device selection',
 '장치 응답 대기 시간이 초과됐습니다. 결과를 검토하고 반복 실행하지 마세요.': 'Device response timed out. Review the result; do '
                                               'not repeat the operation.',
 '장치 조회': 'Device query',
 '장치: ': 'Device: ',
 '장치가 사용 중입니다. 파일 작업을 끝내고 정상 언마운트하세요.': 'Device is in use. Finish file operations and unmount '
                                        'normally.',
 '조회 완료': 'Query complete',
 '조회 중 장치 식별 정보가 변경됐습니다.': 'Device identity changed during the query.',
 '추가 조치가 필요하지 않습니다.': 'No further action required.',
 '커밋 확인된 제거 pending·재연결 검사 → 기본 credential 조회·두 인증·모드·상태 검사 → 증거 보관·pending 해소 (암호 입력·Set 없음)': 'Check '
                                                                                                'committed-removal '
                                                                                                'pending/reconnection '
                                                                                                '→ '
                                                                                                'query '
                                                                                                'default '
                                                                                                'credential/verify '
                                                                                                'both '
                                                                                                'authorities/mode/state '
                                                                                                '→ '
                                                                                                'archive '
                                                                                                'evidence/resolve '
                                                                                                'pending '
                                                                                                '(no '
                                                                                                'password '
                                                                                                'input '
                                                                                                'or '
                                                                                                'Set)',
 '파일 작업을 끝내고 대상 파티션을 정상 언마운트한 뒤 실행하세요.': 'Finish file operations and unmount the target partition '
                                         'normally before running again.',
 '현재 unlock 조건과 다른 응답': 'Response differs from current unlock preconditions',
 '현재 비밀번호 인증이 거부됐습니다. 변경 명령은 진행하지 않았습니다.': 'Current password authentication was rejected. No '
                                           'mutation commands were sent.',
 '현재 암호 입력과 새 암호 입력이 같습니다. 변경하지 않았습니다.': 'Current and new password entries are identical. No '
                                         'changes made.',
 '현재 암호를 확인하고 새 실행으로 다시 시도할 수 있습니다.': 'Check the current password and start a new run.',
 '호스트 목록 조회 완료 · 장치 명령 전송 없음': 'Host listing complete; no device commands sent',
 '호스트 준비 상태: 통과 (장치 상태·pending 검증은 실행 시 수행)': 'Host checks passed (device state and pending '
                                              'verification occur during execution)',
 '화면 결과를 보존하고 저장 위치를 점검하세요. 저장 실패만으로 장치 작업을 반복하지 마세요.': 'Preserve the console result and check the '
                                                        'storage location. Do not repeat device '
                                                        'operations solely because saving failed.',
 '확인 불가': 'Unknown',
 '확인된 오류: ': 'Reported error: ',
 '활성': 'Enabled',
 '후보 암호의 두 credential 검증 완료': 'Candidate password verified for both credentials',
 '언어 선택 (기본: 시스템 로캘)': 'Output language (default: system locale)'}


KO_MESSAGES = {"password input": "암호 입력", "candidate password input": "후보 암호 입력", "pending inspection": "이전 작업 기록 검사",'T7 SSD password (hidden; NOT your Linux sudo password): ': 'T7 SSD 암호 (숨김 입력; Linux sudo 암호가 '
                                                             '아닙니다): ',
 'Current T7 password: ': '현재 T7 암호: ',
 'New T7 password: ': '새 T7 암호: ',
 'Re-enter new T7 password: ': '새 T7 암호 재입력: ',
 'Direct relock is quarantined. Unmount and safely disconnect the SSD.': '직접 재잠금 기능은 격리되어 있습니다. 정상 '
                                                                         '언마운트 후 SSD를 안전하게 분리하세요.',
 'Usage: python3 t7.py [unlock|status|probe|list|change-password|set-password|remove-password|probe-default-credential] [--serial SERIAL] [--execute] [--json] [--save-results]\nDefault: host-only unlock dry-run. --execute enables device commands.\nunlock: T7 Shield by default; one hidden password prompt when locked.\nstatus: Discovery query (Shield by default). probe/list: T7 family diagnostic tools.\nlist / --list: host-only summary; add --json for machine output.\nchange-password/remove-password: --verify-only checks eligible pending; no Set.\nUse COMMAND --help for options. No direct relock or saved credentials.': '사용법: '
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 'python3 '
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 't7.py '
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 '[unlock|status|probe|list|change-password|set-password|remove-password|probe-default-credential] '
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 '[옵션]\n'
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 '기본: '
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 'unlock '
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 'dry-run. '
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 '--execute: '
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 '장치 '
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 '작업 '
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 '실행.\n'
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 'unlock: '
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 '잠긴 '
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 'Shield '
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 '암호 '
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 '숨김 '
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 '입력 '
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 '1회.\n'
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 'status: '
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 'Discovery '
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 '조회. '
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 'probe/list: '
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 'T7 '
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 '계열 '
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 '진단/목록.\n'
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 '--json: '
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 'JSON '
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 '출력. '
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 '--save-results: '
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 '결과 '
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 '저장. '
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 '--serial '
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 'SERIAL: '
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 '대상 '
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 '선택.\n'
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 'change-password/remove-password '
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 '--verify-only: '
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 '지원되는 '
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 'pending '
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 '검증 '
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 '(Set '
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 '없음).\n'
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 'COMMAND '
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 '--help로 '
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 '옵션 '
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 '확인. '
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 '직접 '
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 '재잠금 '
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 '및 '
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 '암호 '
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 '저장 '
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 '기능 '
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 '없음.'}


HELP_TEXT = {
    "en": """Usage: t7 [COMMAND] [OPTIONS]  (source checkout: python3 t7.py)

Commands:
  list                      List T7-family candidates using host information only.
  status                    Query the selected SSD's last-observed lock state.
  probe                     Query INQUIRY/Discovery for compatibility diagnostics.
  unlock                    Unlock with one hidden SSD password entry.
  change-password           Verify the current password and set a new one.
  set-password              Enable password security on an eligible SSD.
  remove-password           Remove password security after verification.
  probe-default-credential  Advanced credential-structure diagnostic; saves no value.

With no COMMAND, show only an unlock dry-run. Actual operations require both
an explicit COMMAND and --execute; list is always host-only.
  --serial SERIAL           Optional when exactly one candidate matches.
  --execute                 Send SSD commands, including status/probe queries.
  --json                    Print JSON instead of a human-readable summary.
  --save-results            Save detailed results to a file; separate operation logs
                            are written for executed operations regardless.
  --allow-unverified-model  Explicit opt-in for unverified T7/T7 Touch operations.
  --lang en|ko              Select output language (default: system locale).

Use COMMAND --help for command options. --list remains a list alias.
Direct relock and saved passwords are not supported.""",
    "ko": """사용법: t7 [명령] [옵션]  (소스 디렉터리: python3 t7.py)

명령:
  list                      호스트 정보로 T7 계열 장치 목록 조회 (장치 명령 없음).
  status                    장치에서 마지막 잠금 상태 조회.
  probe                     INQUIRY·Discovery 호환성 진단.
  unlock                    SSD 암호 숨김 입력 1회로 잠금 해제.
  change-password           현재 암호 확인 후 새 암호 설정.
  set-password              조건이 맞는 장치에 비밀번호 보안 설정.
  remove-password           확인 절차를 거쳐 비밀번호 보안 제거.
  probe-default-credential  기본 credential 구조 진단 (값 저장 없음).

명령을 생략하면 unlock dry-run만 표시합니다. 실제 장치 작업에는 명령과
--execute가 모두 필요합니다. list는 항상 호스트 정보만 조회합니다.
  --serial SERIAL           후보 장치가 정확히 한 대면 생략 가능.
  --execute                 status/probe 조회를 포함한 장치 명령 실행.
  --json                    사람이 읽는 요약 대신 JSON 출력.
  --save-results            상세 결과 파일 저장. 실제 작업 로그는 별도로 기록.
  --allow-unverified-model  미검증 T7/T7 Touch 작업 명시적 허용.
  --lang en|ko              출력 언어 선택 (기본: 시스템 로캘).

명령별 옵션은 '명령 --help'로 확인하세요. --list는 list 별칭입니다.
직접 재잠금이나 암호 저장 기능은 없습니다.""",
}


def help_text():
    """Describe commands and the dry-run/execute boundary in both languages."""
    return HELP_TEXT[LANGUAGE]


def tr(message):
    """Translate known presentation text only; never rewrite arbitrary data."""
    return (EN_MESSAGES if LANGUAGE == "en" else KO_MESSAGES).get(message, message)


def locale_language():
    """Follow LC_ALL > LC_MESSAGES > LANG without mutating process locale."""
    value = next((os.environ[k] for k in ("LC_ALL", "LC_MESSAGES", "LANG") if os.environ.get(k)), "C")
    return "ko" if value.lower().split(".")[0].split("_")[0].split("-")[0] == "ko" else "en"


def stage_text(value):
    """Translate stage labels; keep the protocol command name unchanged."""
    suffix = " (전송 또는 응답 검증)"
    if value.endswith(suffix):
        return value[:-len(suffix)] + tr(suffix)
    return tr(value)


def localized_report(result):
    """Localize a copy of display fields, preserving journal and protocol data."""
    result = dict(result)
    result["language"] = LANGUAGE
    for key in ("plan", "error_stage", "result_save_error_stage"):
        if isinstance(result.get(key), str):
            result[key] = stage_text(result[key]) if key.endswith("stage") else tr(result[key])
    if "diagnostic" in result:
        result["diagnostic"] = dict(result["diagnostic"])
        for key in ("failure_stage", "next_action_message"):
            if isinstance(result["diagnostic"].get(key), str):
                result["diagnostic"][key] = stage_text(result["diagnostic"][key]) if key == "failure_stage" else tr(result["diagnostic"][key])
    return result
