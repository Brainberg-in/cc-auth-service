package com.mpsp.cc_auth_service.utils;

import com.mpsp.cc_auth_service.config.AwsSesConfig;
import org.springframework.beans.factory.annotation.Autowired;
import software.amazon.awssdk.auth.credentials.EnvironmentVariableCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.sesv2.*;
import software.amazon.awssdk.services.sesv2.SesV2Client;
import software.amazon.awssdk.services.sesv2.model.*;

public class CreateSESTemplate {

    public static void main(String[] args) {

        SesV2Client awsSesConfig = SesV2Client.builder().region(Region.AP_SOUTH_1).build();

        // Define the email template
        EmailTemplateContent emailTemplateContent = EmailTemplateContent.builder()
                .subject("Reset Password Link")
                .html("<p>Please click on the link to to reset your password {{link}}</p>")
                .build();
//        UpdateEmailTemplateRequest updateEmailTemplateRequest = UpdateEmailTemplateRequest.builder()
//                .templateName("login_cc_otp") // Template name to update
//                .templateContent(emailTemplateContent)
//                .build();

        CreateEmailTemplateRequest createEmailTemplateRequest = CreateEmailTemplateRequest.builder()
                .templateName("cc_reset_password") // Template name
                .templateContent(emailTemplateContent)
                .build();

        try {
            CreateEmailTemplateResponse response = awsSesConfig.createEmailTemplate(createEmailTemplateRequest);
            System.out.println("Template created! Status: " + response.sdkHttpResponse().statusCode());


        } catch (SesV2Exception e) {
            System.err.println("Failed to create template: " + e.awsErrorDetails().errorMessage());
        } finally {
            awsSesConfig.close();
        }
    }
}
