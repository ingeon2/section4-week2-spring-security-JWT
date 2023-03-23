package com.codestates.config;

import com.codestates.auth.filter.JwtAuthenticationFilter;
import com.codestates.auth.jwt.JwtTokenizer;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

import static org.springframework.security.config.Customizer.withDefaults;



//V1과 바뀐것은 커스텀으로 JWT 토큰 인증에 추가
//@Configuration
public class SecurityConfigurationV2 {
    private final JwtTokenizer jwtTokenizer;

    public SecurityConfigurationV2(JwtTokenizer jwtTokenizer) {
        this.jwtTokenizer = jwtTokenizer;
    }

    //@Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .headers().frameOptions().sameOrigin()
                .and()
                .csrf().disable()
                .cors(withDefaults())
                .formLogin().disable()
                .httpBasic().disable()
                .apply(new CustomFilterConfigurer())
                //추가한 부분,
                //apply() 메서드에 Custom Configurer를 추가해 커스터마이징(customizations)된 Configuration을 추가
                .and()
                .authorizeHttpRequests(authorize -> authorize
                        .anyRequest().permitAll()
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
        configuration.setAllowedMethods(Arrays.asList("GET","POST", "PATCH", "DELETE"));

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }



    //여기가 V1과 비교하여 추가된 부분
    // CustomFilterConfigurer는 우리가 구현한 JwtAuthenticationFilter를 등록하는 역할
    public class CustomFilterConfigurer extends AbstractHttpConfigurer<CustomFilterConfigurer, HttpSecurity> {
        // AbstractHttpConfigurer를 상속해서 Custom Configurer를 구현

        @Override
        public void configure(HttpSecurity builder) throws Exception {  
            // configure() 메서드를 오버라이드해서 Configuration을 커스터마이징(JWT 토큰 사용하도록)
            // configure() 메서드를 오버라이드해서 Configuration을 커스터마이징(JWT 토큰 사용하도록)
            // configure() 메서드를 오버라이드해서 Configuration을 커스터마이징(JWT 토큰 사용하도록)
            // configure() 메서드를 오버라이드해서 Configuration을 커스터마이징(JWT 토큰 사용하도록)


            AuthenticationManager authenticationManager = builder.getSharedObject(AuthenticationManager.class);
            // getSharedObject(AuthenticationManager.class)를 통해 AuthenticationManager의 객체를 얻음
            // Spring Security의 설정을 구성하는 SecurityConfigurer 간에 공유되는 객체를 얻음.

            JwtAuthenticationFilter jwtAuthenticationFilter = new JwtAuthenticationFilter(authenticationManager, jwtTokenizer);
            // JwtAuthenticationFilter를 생성하면서 JwtAuthenticationFilter에서 사용되는 AuthenticationManager와 JwtTokenizer를 DI

            jwtAuthenticationFilter.setFilterProcessesUrl("/v11/auth/login");
            // setFilterProcessesUrl() 메서드를 통해 디폴트 request URL인 “/login”을 “/v11/auth/login”으로 변경

            builder.addFilter(jwtAuthenticationFilter);
            //  addFilter() 메서드를 통해 JwtAuthenticationFilter를 Spring Security Filter Chain에 추가
        }
    }
}
