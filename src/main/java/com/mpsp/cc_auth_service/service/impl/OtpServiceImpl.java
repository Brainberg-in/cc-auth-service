package com.mpsp.cc_auth_service.service.impl;

import com.mpsp.cc_auth_service.dto.User;
import com.mpsp.cc_auth_service.entity.OtpGen;
import com.mpsp.cc_auth_service.repository.OtpGenRepo;
import com.mpsp.cc_auth_service.service.AwsService;
import com.mpsp.cc_auth_service.service.OtpService;
import com.mpsp.cc_auth_service.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Random;

@Service
public class OtpServiceImpl implements OtpService {

    @Autowired
    private UserService userService;

    @Autowired
    private OtpGenRepo otpGenRepo;

    @Autowired
    private AwsService awsService;
    @Override
    public String sendOtp(String email) {
        User user = userService.findByEmail(email);
        if (user == null) {
            throw new UsernameNotFoundException("User not found");
        }
        OtpGen otpGen = otpGenRepo.findByUserId(user.getUserId());
        String otp = String.valueOf(new Random().nextInt(9999));

        //Need to sort the dependencies part.
//        GoogleAuthenticator gAuth = new GoogleAuthenticator();
//
//        // Generate a secret key for the user
//        GoogleAuthenticatorKey key = gAuth.createCredentials();
//        String secret = key.getKey();
//
//        // Generate a 4-digit OTP
//        int otp = gAuth.getTotpPassword(secret);

        awsService.sendEmail(email, "OTP", "Your OTP is: " + otp);
        if(otpGen == null){
            otpGen = new OtpGen();
            otpGen.setUserId(user.getUserId());
            otpGen.setOtp(otp);
            otpGen.setCreatedAt(LocalDateTime.now());
            otpGen.setModifiedAt(LocalDateTime.now());
            otpGenRepo.saveAndFlush(otpGen);
        }else{
            otpGen.setModifiedAt(LocalDateTime.now());
            otpGen.setOtp(otp);
            otpGenRepo.saveAndFlush(otpGen);
        }
        return otp;
    }

    @Override
    public boolean verifyOtp(String email, String otp) {
        User user = userService.findByEmail(email);
        if (user == null) {
            throw new UsernameNotFoundException("User not found");
        }
        OtpGen otpGen = otpGenRepo.findByUserId(user.getUserId());
        if(otpGen == null){
            return false;
        }
        if(otpGen.getModifiedAt().isBefore(LocalDateTime.now().minusHours(1))){
            throw new RuntimeException("OTP expired");
        }
        return otpGen.getOtp().equals(otp);
    }

    @Override
    public void resendOtp(String email) {
        User user = userService.findByEmail(email);
        if (user == null) {
            throw new UsernameNotFoundException("User not found");
        }
        OtpGen otpGen = otpGenRepo.findByUserId(user.getUserId());
        String otp  = sendOtp(email);
        otpGen.setModifiedAt(LocalDateTime.now());
        otpGen.setOtp(otp);
        otpGenRepo.saveAndFlush(otpGen);
    }
}
