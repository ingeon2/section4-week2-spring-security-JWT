package com.codestates.auth.filter;

import com.codestates.auth.dto.LoginDto;
import com.codestates.auth.jwt.JwtTokenizer;
import com.codestates.member.entity.Member;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.SneakyThrows;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;


//로그인 인증 요청을 처리하는 Custom Security Filter
//클라이언트의 로그인 인증 정보를 직접적으로 수신하여 인증 처리의 엔트리포인트(Entrypoint) 역할을 하는 Custom Filter
//나중에 config에서 커스터마이징 해서 사용. (JWT 토큰 위해)
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    //DI
    private final AuthenticationManager authenticationManager;
    private final JwtTokenizer jwtTokenizer;
    public JwtAuthenticationFilter(AuthenticationManager authenticationManager, JwtTokenizer jwtTokenizer) {
        this.authenticationManager = authenticationManager;
        this.jwtTokenizer = jwtTokenizer;
    }

    //메서드 내부에서 인증을 시도하는 로직을 구현
    @SneakyThrows
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {
        ObjectMapper objectMapper = new ObjectMapper();
        //클라이언트에서 전송한 Username과 Password(/auth/login에서 온거)를
        //DTO 클래스로 역직렬화(Deserialization)하기 위해 ObjectMapper 인스턴스를 생성
        LoginDto loginDto = objectMapper.readValue(request.getInputStream(), LoginDto.class);
        //objectMapper.readValue(request.getInputStream(), LoginDto.class)를 통해
        //ServletInputStream 을 LoginDto 클래스의 객체로 역직렬화

        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(loginDto.getUsername(), loginDto.getPassword());
        //Username과 Password 정보를 포함한 UsernamePasswordAuthenticationToken을 생성

        return authenticationManager.authenticate(authenticationToken);
        //UsernamePasswordAuthenticationToken을 AuthenticationManager에게 전달하면서 인증 처리를 위임
    }


    // 클라이언트의 인증 정보를 이용해 인증에 성공할 경우(위의 메서드 성공할 경우) 호출
    @Override
    protected void successfulAuthentication(HttpServletRequest request,
                                            HttpServletResponse response,
                                            FilterChain chain,
                                            Authentication authResult) throws ServletException, IOException {
        Member member = (Member) authResult.getPrincipal();
        //Member 엔티티 클래스의 객체 얻음

        String accessToken = delegateAccessToken(member); //Access Token을 생성
        String refreshToken = delegateRefreshToken(member); //Refresh Token을 생성

        response.setHeader("Authorization", "Bearer " + accessToken);
        //response header(Authorization)에 Access Token을 추가.
        //Access Token은 클라이언트 측에서 백엔드 애플리케이션 측에 요청을 보낼 때마다
        //request header에 추가해서 클라이언트 측의 자격을 증명하는 데 사용

        response.setHeader("Refresh", refreshToken);
        //response header(Refresh)에 Refresh Token을 추가.
        //Refresh Token은 Access Token이 만료될 경우,
        //클라이언트 측이 Access Token을 새로 발급받기 위해 클라이언트에게 추가적으로 제공될 수 있으며
        //Refresh Token을 Access Token과 함께 클라이언트에게 제공할지 여부는
        //애플리케이션의 요구 사항에 따라 달라질 수 있음.

        //위는 로그인 인증에 성공하고, JWT를 생성해서 response header에 추가.

        this.getSuccessHandler().onAuthenticationSuccess(request, response, authResult);
        //onAuthenticationSuccess() 메서드를 호출하면
        //앞에서 우리가 구현한 MemberAuthenticationSuccessHandler의 onAuthenticationSuccess() 메서드가 호출
    }




    //아래는 Access Token과 Refresh Token을 생성하는 구체적인 로직
    private String delegateAccessToken(Member member) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("username", member.getEmail());
        claims.put("roles", member.getRoles());

        String subject = member.getEmail();
        Date expiration = jwtTokenizer.getTokenExpiration(jwtTokenizer.getAccessTokenExpirationMinutes());

        String base64EncodedSecretKey = jwtTokenizer.encodeBase64SecretKey(jwtTokenizer.getSecretKey());

        String accessToken = jwtTokenizer.generateAccessToken(claims, subject, expiration, base64EncodedSecretKey);

        return accessToken;
    }
    private String delegateRefreshToken(Member member) {
        String subject = member.getEmail();
        Date expiration = jwtTokenizer.getTokenExpiration(jwtTokenizer.getRefreshTokenExpirationMinutes());
        String base64EncodedSecretKey = jwtTokenizer.encodeBase64SecretKey(jwtTokenizer.getSecretKey());

        String refreshToken = jwtTokenizer.generateRefreshToken(subject, expiration, base64EncodedSecretKey);

        return refreshToken;
    }
}
