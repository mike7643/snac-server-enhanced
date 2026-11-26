package com.ureca.snac.auth.controller.verify;

import com.ureca.snac.auth.dto.request.PhoneRequest;
import com.ureca.snac.auth.dto.request.VerificationPhoneRequest;
import com.ureca.snac.auth.service.verify.SnsService;
import com.ureca.snac.common.ApiResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import static com.ureca.snac.common.BaseCode.*;

@RestController
@RequiredArgsConstructor
public class SnsController implements SnsControllerSwagger {

    private final SnsService snsService;

    @Override
    public ResponseEntity<ApiResponse<Void>> sendVerificationCode(@Valid @RequestBody PhoneRequest dto) {
        snsService.sendVerificationCode(dto.getPhone());
        return ResponseEntity.ok(ApiResponse.ok(SMS_VERIFICATION_SENT));
    }

    @Override
    public ResponseEntity<ApiResponse<Void>> verifyCode(@Valid @RequestBody VerificationPhoneRequest dto) {
        snsService.verifyCode(dto.getPhone(), dto.getCode());
        return ResponseEntity.ok(ApiResponse.ok(SMS_CODE_VERIFICATION_SUCCESS));
    }
}
