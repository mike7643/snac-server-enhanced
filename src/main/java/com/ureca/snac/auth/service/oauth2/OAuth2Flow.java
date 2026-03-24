package com.ureca.snac.auth.service.oauth2;

// OAuth 로그인 요청이 "연동"인지 "로그인"인지 판별한 결과를 담는 값 객체.
public record OAuth2Flow(boolean linking, String emailFromState) {

    public static OAuth2Flow linking(String emailFromState) {
        return new OAuth2Flow(true, emailFromState);
    }

    public static OAuth2Flow login() {
        return new OAuth2Flow(false, null);
    }
}
