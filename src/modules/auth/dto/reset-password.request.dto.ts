
import { IsString, IsNotEmpty, Validate  } from "class-validator";
import { ValidatorConstraint, ValidatorConstraintInterface, ValidationArguments } from "class-validator";


@ValidatorConstraint({ name: 'MatchesPassword', async: false })
export class MatchesPassword implements ValidatorConstraintInterface {
    validate(confirmPassword: string, validationArguments?: ValidationArguments): Promise<boolean> | boolean {
        const obj = validationArguments?.object as { password: string }
        return obj.password === confirmPassword
    }

    defaultMessage(validationArguments?: ValidationArguments): string {
        console.log(validationArguments)
        return 'Xác nhận mật khẩu không chính xác'
    }
} 


export class ResetPasswordRequest {

    @IsString({message: "Token phải là kiểu chuỗi"})
    @IsNotEmpty({message: "Token không được để trống"})
    token: string;

    @IsString({message: "Mật khẩu phải là kiểu chuỗi"})
    @IsNotEmpty({message: "Mật khẩu không được để trống"})
    password: string;

    @IsString({message: "Mật khẩu phải là kiểu chuỗi"})
    @IsNotEmpty({message: "Mật khẩu không được để trống"})
    @Validate(MatchesPassword, { message: 'Xác nhận mật khẩu không khớp với mật khẩu'})
    confirmPassword: string;

}