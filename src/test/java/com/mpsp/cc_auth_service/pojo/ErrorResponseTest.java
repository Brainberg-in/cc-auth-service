package com.mpsp.cc_auth_service.pojo;

import com.mpsp.cc_auth_service.error.ErrorResponse;
import com.openpojo.reflection.PojoClass;
import com.openpojo.reflection.impl.PojoClassFactory;
import com.openpojo.validation.Validator;
import com.openpojo.validation.ValidatorBuilder;
import com.openpojo.validation.rule.impl.EqualsAndHashCodeMatchRule;
import com.openpojo.validation.rule.impl.GetterMustExistRule;
import com.openpojo.validation.rule.impl.SetterMustExistRule;
import com.openpojo.validation.test.impl.GetterTester;
import com.openpojo.validation.test.impl.SetterTester;
import org.junit.jupiter.api.Test;

public class ErrorResponseTest {

  @Test
  public void testPojoStructureAndBehavior() {
    final PojoClass pojoClass = PojoClassFactory.getPojoClass(ErrorResponse.class);
    final Validator validator =
        ValidatorBuilder.create()
            // Add Rules to validate structure for POJO_PACKAGE
            // See com.openpojo.validation.rule.impl for more ...
            //
            // Add Testers to validate behaviour for POJO_PACKAGE
            // See com.openpojo.validation.test.impl for more ...
            .with(new GetterMustExistRule())
            .with(new SetterMustExistRule())
            .with(new SetterTester())
            .with(new GetterTester())
            .with(new EqualsAndHashCodeMatchRule())
            .build();

    validator.validate(pojoClass);
  }
}
