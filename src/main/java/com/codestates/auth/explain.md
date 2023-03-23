userdetails, utils 패키지들이 원래 password 추가해서 스프링 시큐리티 사용하는 세션로직이었다면,  
dto, filter, jwt 추가되어 스프링 시큐리티에 JWT 토큰 사용하는 로직 추가해주었고,  
handler 패키지로 로그인 성공로직, 실패로직 configV3, JwtAuthenticationFilter 클래스에 구현했다.  
JwtVerificationFilter 클래스는 JWT를 검증하기 위해 만든 클래스이다.  
  
  
AuthenticationEntryPoint는  
SignatureException, ExpiredJwtException 등 Exception 발생으로 인해 SecurityContext에 Authentication이 저장되지 않을 경우 등  
AuthenticationException이 발생할 때 호출되는 핸들러 같은 역할.  
  
MemberAccessDeniedHandler는 인증에는 성공했지만 해당 리소스에 대한 권한이 없으면 호출되는 핸들러.  
  
ErrorResponder 클래스는 ErrorResponse를 출력 스트림으로 생성하는 역할.(바로 위 두개 클래스에서 사용.)  
