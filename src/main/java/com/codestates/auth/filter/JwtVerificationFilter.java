package com.codestates.auth.filter;

import com.codestates.auth.jwt.JwtTokenizer;
import com.codestates.auth.utils.CustomAuthorityUtils;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.security.SignatureException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.Map;

//JWT를 검증하는 전용 Security Filter를 구현
public class JwtVerificationFilter extends OncePerRequestFilter {
    //OncePerRequestFilter를 확장해서 request 당 한 번만 실행되는 Security Filter를 구현

    //DI
    //JwtTokenizer는 JWT를 검증하고 Claims(토큰에 포함된 정보)를 얻는 데 사용
    //CustomAuthorityUtils는 JWT 검증에 성공하면 Authentication 객체에 채울 사용자의 권한을 생성하는 데 사용
    private final JwtTokenizer jwtTokenizer;
    private final CustomAuthorityUtils authorityUtils;
    public JwtVerificationFilter(JwtTokenizer jwtTokenizer, CustomAuthorityUtils authorityUtils) {
        this.jwtTokenizer = jwtTokenizer;
        this.authorityUtils = authorityUtils;
    }


    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        
        //JWT 검증 과정에서 발생할 수 있는 Exception을 처리할 수 있는 예외 처리 로직을 JwtVerificationFilter에 추가(트라이 캐치)
        
        
        try {
            Map<String, Object> claims = verifyJws(request);
            //JWT를 검증하는데 사용되는 private 메서드
            setAuthenticationToContext(claims);
            //setAuthenticationToContext() 메서드는 Authentication 객체를 SecurityContext에 저장하기 위한 private 메서드
        }
        catch (SignatureException se) {
            request.setAttribute("exception", se);
        }
        catch (ExpiredJwtException ee) {
            request.setAttribute("exception", ee);
        }
        catch (Exception e) {
            request.setAttribute("exception", e);
        }

        filterChain.doFilter(request, response);
        //문제없이 JWT의 서명 검증에 성공하고, Security Context에 Authentication을 저장한 뒤에는 
        //위와 같이 다음(Next) Security Filter를 호출

    }

    //OncePerRequestFilter의 shouldNotFilter()를 오버라이드 한 것으로,
    //특정 조건에 부합하면(true이면) 해당 Filter의 동작을 수행하지 않고 다음 Filter로 건너뛰도록 해줌.
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        String authorization = request.getHeader("Authorization");
        //Authorization header의 값을 얻은 후에

        return authorization == null || !authorization.startsWith("Bearer");
        //Authorization header의 값이 null이거나 Authorization header의 값이 “Bearer”로 시작하지 않는다면
        //해당 Filter의 동작을 수행하지 않도록 정의

        //이 말의 의미는 JWT가 Authorization header에 포함되지 않았다면 JWT 자격증명이 필요하지 않은 리소스에 대한 요청이라고 판단하고
        //다음(Next) Filter로 처리를 넘기는 것
    }




    private Map<String, Object> verifyJws(HttpServletRequest request) {
        String jws = request.getHeader("Authorization").replace("Bearer ", "");
        //request의 header에서 JWT를 얻음 (토큰에서 헤더 가져온 후 Bearer제거)

        String base64EncodedSecretKey = jwtTokenizer.encodeBase64SecretKey(jwtTokenizer.getSecretKey());
        //JWT 서명(Signature)을 검증하기 위한 Secret Key를 얻음.

        Map<String, Object> claims = jwtTokenizer.getClaims(jws, base64EncodedSecretKey).getBody();
        //JWT에서 위에서 얻은 key값으로 Claims를 파싱

        // JWT에서 Claims를 파싱할 수 있다는 의미는 내부적으로 서명(Signature) 검증에 성공했다는 의미
        // verify() 같은 검증 메서드가 따로 존재하는 것이 아니라 Claims가 정상적으로 파싱이 되면 서명 검증 역시 자연스럽게 성공했다는 사실을 꼭 기억

        return claims;
    }

    private void setAuthenticationToContext(Map<String, Object> claims) {
        String username = (String) claims.get("username");
        //JWT에서 파싱한 Claims에서 username을 얻음

        List<GrantedAuthority> authorities = authorityUtils.createAuthorities((List) claims.get("roles"));
        //JWT의 Claims에서 얻은 권한 정보를 기반으로 List<GrantedAuthority 를 생성

        Authentication authentication = new UsernamePasswordAuthenticationToken(username, null, authorities);
        //username과 List<GrantedAuthority 를 포함한 Authentication 객체를 생성

        SecurityContextHolder.getContext().setAuthentication(authentication);
        //SecurityContext에 Authentication 객체를 저장
    }
}
