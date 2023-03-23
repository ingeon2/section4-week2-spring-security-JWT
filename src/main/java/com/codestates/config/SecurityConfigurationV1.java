package com.codestates.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

import static org.springframework.security.config.Customizer.withDefaults;

//@Configuration
public class SecurityConfigurationV1 {

    //@Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .headers().frameOptions().sameOrigin()
                //H2 웹 콘솔의 화면 자체가 내부적으로 태그(<frame>)를 사용하고 있기 때문에 사용 불가.
                // 개발 환경에서는 H2 웹 콘솔을 정상적으로 사용할 수 있도록 사용한 매서드.

                .and()

                .csrf().disable()
                //Cross Site Request Forgery의 약자로, 한글 뜻으로는 사이트간 요청 위조를 뜻함,
                //disable 사용불가.

                .cors(withDefaults())
                //CORS(Cross-Origin Resource Sharing)
                //CORS 설정을 추가합니다. .cors(withDefaults()) 일 경우, corsConfigurationSource라는 이름으로 등록된 Bean을 이용
                //애플리케이션 간에 출처(Origin)가 다를 경우 스크립트 기반의 HTTP 통신(XMLHttpRequest, Fetch API)을 통한 리소스 접근이 제한
                //CORS는 출처가 다른 스크립트 기반 HTTP 통신을 하더라도 선택적으로 리소스에 접근할 수 있는 권한을 부여하도록 브라우저에 알려주는 정책

                .formLogin().disable()
                //CSR(Client Side Rendering) 방식에서 주로 사용하는 JSON 포맷으로 Username과 Password를 전송하는 방식을 사용,
                //위 와 같이 폼 로그인 방식을 비활성화

                .httpBasic().disable()
                //HTTP Basic 인증은 request를 전송할 때마다 Username/Password 정보를 HTTP Header에 실어서 인증을 하는 방식
                //사용하지 않으므로 위와 같이 HTTP Basic 인증 방식을 비활성화


                .authorizeHttpRequests(authorize ->
                        authorize.anyRequest().permitAll()
                        //JWT를 적용하기 전이므로 우선은 모든 HTTP request 요청에 대해서 접근을 허용하도록 설정
                );

        return http.build();
    }


    //PasswordEncoder Bean 객체를 생성
    //@Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    //CorsConfigurationSource Bean 생성을 통해 구체적인 CORS 정책을 설정
    //@Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList("*"));
        //모든 출처(Origin)에 대해 스크립트 기반의 HTTP 통신을 허용하도록 설정
        configuration.setAllowedMethods(Arrays.asList("GET","POST", "PATCH", "DELETE"));
        //파라미터로 지정한 HTTP Method에 대한 HTTP 통신을 허용

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        //CorsConfigurationSource 인터페이스의 구현 클래스인 UrlBasedCorsConfigurationSource 클래스의 객체를 생성
        source.registerCorsConfiguration("/**", configuration);
        //모든 URL에 앞에서 구성한 CORS 정책(CorsConfiguration)을 적용
        return source;
    }

}
