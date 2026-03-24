package com.ureca.snac.auth.service.oauth2;

import com.ureca.snac.auth.oauth2.SocialProvider;
import com.ureca.snac.auth.repository.AuthRepository;
import com.ureca.snac.member.entity.Member;
import com.ureca.snac.member.entity.SocialLink;
import com.ureca.snac.member.repository.SocialLinkRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

import static com.ureca.snac.common.BaseCode.MEMBER_NOT_FOUND;
import static com.ureca.snac.common.BaseCode.OAUTH_DB_ACCOUNT_NOT_FOUND;
import static com.ureca.snac.common.BaseCode.OAUTH_DB_ALREADY_LINKED;

@Slf4j
@Service
@RequiredArgsConstructor
public class SocialAccountService {

    private final AuthRepository authRepository;
    private final SocialLinkRepository socialLinkRepository;

    @Transactional
    public Member linkOrGetMember(SocialProvider provider, String providerId, String emailFromState) {
        // providerId가 이미 연동돼 있으면 "같은 계정 재연동"만 허용한다.
        Optional<SocialLink> alreadyLinked = socialLinkRepository.findByProviderAndProviderId(provider, providerId);
        if (alreadyLinked.isPresent()) {
            Member linkedMember = alreadyLinked.get().getMember();
            if (linkedMember.getEmail().equals(emailFromState)) {
                log.info("같은 계정에 이미 연동된 소셜 계정입니다. provider={}, id={}", provider, providerId);
                return linkedMember;
            }

            log.warn("이미 다른 계정에 연동된 소셜 계정: provider={}, id={}", provider, providerId);
            throw new OAuth2AuthenticationException(
                    new OAuth2Error(OAUTH_DB_ALREADY_LINKED.getCode()),
                    "이미 다른 계정에 연동된 소셜 계정입니다.");
        }

        Member member = authRepository.findByEmail(emailFromState)
                .orElseThrow(() -> {
                    log.error("존재하지 않는 회원 이메일: {}", emailFromState);
                    return new OAuth2AuthenticationException(
                            new OAuth2Error(MEMBER_NOT_FOUND.getCode()),
                            "해당 회원을 찾을 수 없습니다.");
                });

        // 새 연동은 회원 엔티티에 링크를 추가하고 저장한다.
        member.addSocialLink(provider, providerId);
        authRepository.save(member);
        log.info("social 연동 완료: {} -> {}", member.getEmail(), provider);
        return member;
    }

    @Transactional(readOnly = true)
    public Member getLinkedMemberForLogin(SocialProvider provider, String providerId) {
        // 로그인은 "이미 연동된 providerId"가 있어야만 성공한다.
        SocialLink socialLink = socialLinkRepository.findByProviderAndProviderId(provider, providerId)
                .orElseThrow(() -> {
                    log.warn("연동된 소셜 계정이 아님: provider={}, id={}", provider, providerId);
                    return new OAuth2AuthenticationException(
                            new OAuth2Error(OAUTH_DB_ACCOUNT_NOT_FOUND.getCode()),
                            "소셜 계정에 연동된 계정이 없습니다. 회원가입을 먼저 진행해주세요.");
                });
        return socialLink.getMember();
    }
}
