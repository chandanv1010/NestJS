import { IsEmail, IsString, IsNotEmpty, MinLength  } from "class-validator";

export class AuthRequest {

    @IsEmail({}, {message: "Email không đúng định dạng"})
    @IsString({message: "Email phải là kiểu chuỗi"})
    @IsNotEmpty({message: "Email không được để trống"})
    email: string;

    @IsString({message: "Mật khẩu phải là chuỗi kí tự"})
    @IsNotEmpty({message: "Mật khẩu không được để trống"})
    @MinLength(6, {message: "Mật khẩu phải có tối thiểu 6 kí tự"})
    password: string;
}