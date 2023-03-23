package com.codestates.auth.handler;


import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

//로그인 인증 성공 및 실패에 따른 추가 처리 (필수 아닌 추가 기능)
//로그인 인증 성공 시 추가 작업을 할 수 있는 MemberAuthenticationSuccessHandler
@Slf4j
public class MemberAuthenticationSuccessHandler implements AuthenticationSuccessHandler {
    //우리가 직접 정의하는 Custom AuthenticationSuccessHandler는 위와 같이 AuthenticationSuccessHandler 인터페이스를 구현해야 함.



    // 단순히 로그만 출력하고 있지만
    // Authentication 객체에 사용자 정보를 얻은 후, HttpServletResponse로 출력 스트림을 생성하여 response를 전송할 수 있다는 사실을 기억
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException {
        // 인증 성공 후, 로그를 기록하거나 사용자 정보를 response로 전송하는 등의 추가 작업을 할 수 있다.
        log.info("# Authenticated successfully!");
    }
}
