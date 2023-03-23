package com.codestates.auth.dto;

//로그인 인증 정보 역직렬화(Deserialization)를 위한 LoginDTO 클래스 생성
//클라이언트가 전송한 Username/Password 정보를 Security Filter에서 사용할 수 있도록 역직렬화(Deserialization)하기 위한 DTO 클래스
import lombok.Getter;

@Getter
public class LoginDto {
    private String username;
    private String password;
}
