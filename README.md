우선 JWT사용을 위해 config패키지에서 SEcurityConfig 클래스 추가.
이후
Spring Security가 적용되지 않았던 여러분들의 커피 주문 샘플 애플리케이션에는
회원 등록 시, 회원의 인증과 관련된 정보(패스워드, 사용자 권한)가 필요없었지만
이번 챕터에는 필요.
즉, Dto, 엔티티 클래스, CustomAuthorityUtils 수정(패스워드).  
  
  
  
사용자의 로그인 인증 성공 후, JWT가 클라이언트에게 전달되는 과정은 다음과 같습니다.  

1클라이언트가 서버 측에 로그인 인증 요청(Username/Password를 서버 측에 전송)    
2로그인 인증을 담당하는 Security Filter(JwtAuthenticationFilter)가 클라이언트의 로그인 인증 정보 수신  
3Security Filter가 수신한 로그인 인증 정보를 AuthenticationManager에게 전달해 인증 처리를 위임  
4AuthenticationManager가 Custom UserDetailsService(MemberDetailsService)에게 사용자의 UserDetails 조회를 위임  
5Custom UserDetailsService(MemberDetailsService)가 사용자의 크리덴셜을 DB에서 조회한 후, AuthenticationManager에게 사용자의 UserDetails를 전달  
6AuthenticationManager가 로그인 인증 정보와 UserDetails의 정보를 비교해 인증 처리  
7JWT 생성 후, 클라이언트의 응답으로 전달  

1번부터 7번 과정 중에서 우리는 JwtAuthenticationFilter 구현(2번 ~ 3번, 7번), MemberDetailsService(5번)을 구현.  
4번과 6번은 Spring Security의 AuthenticationManager가 대신 처리해주므로 신경 쓸 필요가 없음.  
  
  
위의 역할을 위해 auth 패키지 안의 클래스를 전부 생성해줌.  각각 안에 주석과 역할이 알려져있음.  
  
  
나온 에러 : 환경 변수 설정은 재부팅 후 완료된다,  
this확실히 이해할것.  

핵심 포인트  
UsernamePasswordAuthenticationFilter를 이용해서 JWT 발급 전의 로그인 인증 기능을 구현할 수 있다.  
Spring Security에서는 개발자가 직접 Custom Configurer를 구성해  
Spring Security의 Configuration을 커스터마이징(customizations) 할 수 있다.  
Username/Password 기반의 로그인 인증은 OncePerRequestFilter 같은  
Spring Security에서 지원하는 다른 Filter를 이용해서 구현할 수 있으며,  
Controller에서 REST API 엔드포인트로 구현하는 것도 가능하다.  
Spring Security에서는 Username/Password 기반의 로그인 인증에 성공했을 때,  
로그를 기록하거나 로그인에 성공한 사용자 정보를 response로 전송하는 등의 추가 처리를 할 수 있는  
AuthenticationSuccessHandler를 지원하며,  
로그인 인증 실패 시에도 마찬가지로 인증 실패에 대해 추가 처리를 할 수 있는 AuthenticationFailureHandler를 지원한다.  
  
  
  
이제  
로그인 인증 후, response로 전달받은 JWT를  
HTTP request header에 포함하여 request를 전송할 때마다  
서버 측에서 request header에 포함된 JWT를 검증하는 기능만 구현하면  
JWT를 이용한 인증 및 자격 검증 기능이 완성.  


JWT를 검증하는 전용 Security Filter(JwtVerificationFilter 클래스)를 구현.  
