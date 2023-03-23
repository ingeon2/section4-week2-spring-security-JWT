package com.codestates.member.dto;

import com.codestates.member.entity.Member;
import com.codestates.stamp.Stamp;
import com.codestates.validator.NotSpace;
import lombok.AllArgsConstructor;
import lombok.Getter;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Pattern;

public class MemberDto {
    @Getter
    @AllArgsConstructor // 테스트에서 사용하려고 추가해줌
    public static class Post {

        //Spring Security가 적용되지 않았던 여러분들의 커피 주문 샘플 애플리케이션에는 
        //회원 등록 시, 회원의 인증과 관련된 정보(패스워드, 사용자 권한)가 필요없었지만 
        //여기선 회원의 패스워드 정보를 전달받기 위해 필요
        @NotBlank
        private String password;



        @NotBlank
        @Email
        private String email;

        @NotBlank(message = "이름은 공백이 아니어야 합니다.")
        private String name;

        @Pattern(regexp = "^010-\\d{3,4}-\\d{4}$",
                message = "휴대폰 번호는 010으로 시작하는 11자리 숫자와 '-'로 구성되어야 합니다.")
        private String phone;
    }

    @Getter
    @AllArgsConstructor
    public static class Patch {
        private long memberId;

        @NotSpace(message = "회원 이름은 공백이 아니어야 합니다")
        private String name;

        @NotSpace(message = "휴대폰 번호는 공백이 아니어야 합니다")
        @Pattern(regexp = "^010-\\d{3,4}-\\d{4}$",
                message = "휴대폰 번호는 010으로 시작하는 11자리 숫자와 '-'로 구성되어야 합니다")
        private String phone;

        private Member.MemberStatus memberStatus;


        public void setMemberId(long memberId) {
            this.memberId = memberId;
        }
    }

    @AllArgsConstructor
    @Getter
    public static class Response {
        private long memberId;
        private String email;
        private String name;
        private String phone;
        private Member.MemberStatus memberStatus;
        private Stamp stamp;

        public String getMemberStatus() {
            return memberStatus.getStatus();
        }
        public int getStamp() {
            return stamp.getStampCount();
        }
    }
}
