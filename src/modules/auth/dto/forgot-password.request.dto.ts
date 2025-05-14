
import { IsEmail, IsString, IsNotEmpty  } from "class-validator";

export class ForgotPasswordRequest {

    @IsEmail({}, {message: "Email không đúng định dạng"})
    @IsString({message: "Email phải là kiểu chuỗi"})
    @IsNotEmpty({message: "Email không được để trống"})
    email: string;

}