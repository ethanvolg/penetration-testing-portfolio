# SQL injection

| **보고서 ID** | **플랫폼 (타겟)**        | **취약 기능 / 엔드포인트**           | **취약 파라미터**               | **공격 유형**           | **주요 접근 방식 및 보안 우회**                              |
| ------------- | ------------------------ | ------------------------------------ | ------------------------------- | ----------------------- | ------------------------------------------------------------ |
| **531051**    | Starbucks (웹 서비스)    | XML 파일 업로드                      | `MainAccount` (XML 노드)        | Blind (Time-based)      | XML에서 금지된 `'` 문자를 `'` 엔티티로 우회.                 |
| **297478**    | GSA (labs.data.gov)      | 대시보드 (`/csv_to_json`)            | `User-Agent` (HTTP 헤더)        | Blind (Time-based)      | 일반적인 입력값이 아닌 HTTP 헤더를 타겟팅.                   |
| **403616**    | Zomato (웹)              | 메뉴 아이템 태그 추가                | `item_id` (POST)                | Blind (Time-based)      | Akamai WAF를 `/*f*/` 같은 주석으로 우회. DB 캐싱을 우회하기 위해 요청마다 파라미터의 정수 값을 변경. |
| **761304**    | MTN Group (웹)           | 검색 (`/index.php`)                  | `lang` (Cookie)                 | In-band (Error-based)   | GET/POST가 아닌 **쿠키** 파라미터에서 취약점 발견.           |
| **962889**    | Acronis (API)            | 유닛 설정 (`/unit_configurations`)   | `unit` (GET)                    | In-band (Error-based)   | `extractvalue()` 함수를 사용한 에러 기반 공격.               |
| **592400**    | Starbucks (API)          | 미인증 WSDL 테스트 API               | API 함수 파라미터               | Blind (SQLi) -> **RCE** | 인증 없이 노출된 **테스트용 API**를 악용. `xp_cmdshell`을 통해 RCE로 연계. |
| **549355**    | Starbucks (웹)           | 음료 상세 페이지                     | URL 파라미터 (미지정)           | Blind (SQLi)            | WAF 우회. (구체적인 우회 기법은 비공개)                      |
| **273946**    | Grab (워드프레스)        | `Formidable Pro` 플러그인            | `order` (Shortcode 파라미터)    | Blind (Boolean-based)   | 플러그인의 숏코드 내부 파라미터라는 복잡한 지점을 공략. 쉼표(`,`) 필터링을 `sqlmap`의 `commalesslimit` 탬퍼 스크립트로 우회. |
| **435066**    | HackerOne (웹)           | GraphQL 엔드포인트                   | `embedded_submission_form_uuid` | Blind (Time-based)      | GraphQL *입력(input)*이 아닌 *파라미터(parameter)*가 `SET SESSION` 구문에 직접 삽입되는 문제 이용. **스택 쿼리**(`;`)로 `pg_sleep()` 실행. |
| **1039315**   | Automattic (웹)          | API (`/reader_api/stories.php`)      | `search` (GET)                  | Blind (Time-based)      | 일반적인 GET 파라미터에서의 Time-based 공격.                 |
| **1224660**   | Acronis (웹)             | 로그인 (`/wp-login.php`)             | `log` (POST)                    | Blind (Time-based)      | **#1109311** 리포트의 픽스를 `XOR` 연산자를 사용해 우회.     |
| **2958619**   | MTN Group (웹)           | URL 경로                             | `customerId` (URL Path)         | In-band (Error-based)   | `/.../customerId/732562'/...` 처럼 URL 경로 자체의 값을 파라미터로 사용하는 로직을 공략. |
| **952501**    | Zomato (API)             | 리더보드 (`/leaderboard_v2.json`)    | 다른 파라미터 (내부 발견)       | Blind (Boolean-based)   | 해커는 Solr Injection을 보고했으나, Zomato 팀이 해당 코드 리뷰 중 **다른 파라미터**에서 실제 SQLi(Blind)를 발견함. |
| **1525200**   | Palantir (웹)            | MOVEit Transfer (서드파티)           | CVE-2021-38159                  | SQLi (미지정)           | 패치되지 않은 서드파티 소프트웨어의 **알려진 CVE**를 악용.   |
| **2633959**   | MTN Group (웹)           | URL 경로                             | `customerId` (URL Path)         | In-band (Error-based)   | #2958619와 동일. URL 경로 값을 파라미터로 사용.              |
| **1069561**   | Automattic (웹)          | API (`/js/importStatus.php`)         | `acctid` (GET)                  | Blind (Boolean/Time)    | 일반적인 GET 파라미터에서의 Blind SQLi.                      |
| **1109311**   | Acronis (웹)             | 로그인 (`/wp-login.php`)             | `log` (POST)                    | Blind (SQLi)            | 일반적인 로그인 파라미터. (#1224660에서 우회됨)              |
| **2312334**   | U.S. DoD (웹)            | 출판물 (`/pubs/index.php`)           | `authors` (POST)                | Blind (Time-based)      | `XOR` 연산자를 이용한 Time-based 공격.                       |
| **2209130**   | Mozilla (API)            | 회원가입 (`/interaction/.../signup`) | `invite_code` (POST)            | Blind (Time-based)      | **스택 쿼리**(`;`)를 이용해 `PG_SLEEP()`를 실행. (PostgreSQL 타겟) |
| **150156**    | Uber (웹 서비스)         | 이메일 수신 거부                     | `user_id` (JSON 내부)           | Blind (Time-based)      | `p` 파라미터에 **Base64**로 인코딩된 **JSON** 객체가 있었음. 이를 디코딩하여 내부의 `user_id` 값에 페이로드를 주입 후 다시 인코딩하여 전송. |
| **3198980**   | Automattic (WooCommerce) | 관리자 리포트 (`/wp-admin/`)         | `coupon_codes` (GET)            | Blind (Time-based)      | 관리자 권한(리포트 조회)이 필요. `sanitize_text_field` 함수를 우회하는 `UNION` 구문 사용. |
| **2737595**   | U.S. DoD (웹)            | 필터 기능                            | `filter[event]` (GET)           | Blind (Boolean/Time)    | `filter[event]`처럼 배열 형태로 전송되는 복잡한 파라미터 이름을 타겟팅. |
| **995122**    | U.S. DoD (웹)            | `/DNCdb.php`                         | `Referer` (HTTP 헤더)           | Blind (Time-based)      | WAF가 데이터 추출은 차단했으나 Time-based 공격은 허용. `alert=` 파라미터가 URL에 존재할 때만 트리거되는 특수 조건 발견. |
| **1893800**   | HackerOne (웹)           | CVE 검색 (GraphQL)                   | `search`                        | Blind (Boolean-based)   | 검색어를 공백으로 분리 후 `ILIKE` 구문에 단순 문자열 삽입. `Arel`을 사용하도록 수정하여 픽스. |
| **3292573**   | Django (프레임워크)      | Django ORM                           | `FilteredRelation`의 *별칭*     | SQLi -> **RCE**         | 프레임워크 자체의 취약점. `annotate()`의 별칭(alias)이 `select_related()`에서 검증 없이 사용됨. PostgreSQL의 `COPY...PROGRAM`으로 RCE까지 시연. |
| **390879**    | U.S. DoD (웹)            | `.cfm` (ColdFusion) 페이지           | `countID` (GET)                 | SQLi (미지정)           | 일반적인 GET 파라미터 SQLi. (MS-SQL 타겟)                    |
| **1042746**   | Automattic (웹)          | API (`/changeReplaceOpt.php`)        | `acctid` (GET)                  | Blind (Time-based)      | 일반적인 GET 파라미터 SQLi.                                  |
| **2597543**   | U.S. DoD (웹)            | 메인 페이지                          | `User-Agent` (HTTP 헤더)        | Blind (Boolean-based)   | 또 다른 `User-Agent` 헤더 기반 인젝션.                       |
| **419017**    | U.S. DoD (웹)            | `.aspx` 페이지                       | `SSN` (Form 필드)               | Classic (Boolean-based) | `maxlength="9"`로 설정된 **클라이언트 사이드 유효성 검사**를 브라우저 개발자 도구로 제거하고 페이로드를 전송하여 우회. |
| **300176**    | Zomato (웹)              | 로그인 페이지                        | `orange`, `squeeze` (Cookie)    | Blind (Time/Boolean)    | `orange` 쿠키는 Time-based, `squeeze` 쿠키는 Boolean-based에 취약. 비정상적인 이름의 쿠키를 타겟팅. |
| **1034625**   | Informatica (API)        | 토큰 갱신 (`/api/v1/token`)          | `refresh_token` (POST)          | Blind (Time-based)      | `WAITFOR DELAY` (MS-SQL) 페이로드 사용. 패치되지 않은 서드파티 제품의 취약점. |
| **838855**    | Zomato (웹)              | API (`/php/geto2banner`)             | `res_id` (POST)                 | Blind (Time-based)      | `/**/` 주석을 이용해 공백 필터링 우회.                       |
| **2599826**   | U.S. DoD (웹)            | `.mil` 사이트                        | `User-Agent` (HTTP 헤더)        | Blind (Boolean-based)   | 세 번째 `User-Agent` 헤더 기반 인젝션.                       |
| **1878584**   | U.S. Dept of State (웹)  | 검색                                 | POST Body 파라미터              | Blind (Time-based)      | WAF가 403 에러를 반환하며 방어했지만, Time-based Blind 공격은 차단하지 못함. |
