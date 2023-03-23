package com.codestates.auth.handler;


import com.codestates.response.ErrorResponse;
import com.google.gson.Gson;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

//로그인 인증 성공 및 실패에 따른 추가 처리 (필수 아닌 추가 기능)
//로그인 인증 실패 시, 추가 작업을 할 수 있는 MemberAuthenticationFailureHandler
@Slf4j
public class MemberAuthenticationFailureHandler implements AuthenticationFailureHandler {
    //우리가 직접 정의하는 Custom AuthenticationFailureHandler는 위와 같이 AuthenticationFailureHandler 인터페이스를 구현해야 함
    
    @Override
    public void onAuthenticationFailure(HttpServletRequest request,
                                        HttpServletResponse response,
                                        AuthenticationException exception) throws IOException {
        // 인증 실패 시, 에러 로그를 기록하거나 error response를 전송할 수 있다.
        log.error("# Authentication failed: {}", exception.getMessage());

        sendErrorResponse(response);
        //아래의 sendErrorResponse() 메서드를 호출해 출력 스트림에 Error 정보를 담음
    }

    private void sendErrorResponse(HttpServletResponse response) throws IOException {
        Gson gson = new Gson();
        //Error 정보가 담긴 객체(ErrorResponse)를 JSON 문자열로 변환하는데 사용되는 Gson 라이브러리의 인스턴스를 생성

        ErrorResponse errorResponse = ErrorResponse.of(HttpStatus.UNAUTHORIZED);
        //ErrorResponse 객체를 생성합니다. ErrorResponse.of() 메서드로 HttpStatus.UNAUTHORIZED 상태 코드를 전달

        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        //response의 Content Type이 “application/json” 이라는 것을 클라이언트에게 알려줄 수 있도록
        //MediaType.APPLICATION_JSON_VALUE를 HTTP Header에 추가

        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        // response의 status가 401임을 클라이언트에게 알려줄 수 있도록 HttpStatus.UNAUTHORIZED.value()을 HTTP Header에 추가

        response.getWriter().write(gson.toJson(errorResponse, ErrorResponse.class));
        //Gson을 이용해 ErrorResponse 객체를 JSON 포맷 문자열로 변환 후, 출력 스트림을 생성.
    }
}

