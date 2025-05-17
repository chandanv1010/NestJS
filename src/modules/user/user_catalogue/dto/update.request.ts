/* eslint-disable @typescript-eslint/no-unsafe-call */
import { IsString, IsNotEmpty } from "class-validator";

export class UpdateRequest {

    @IsString({message: "Email phải là kiểu chuỗi"})
    @IsNotEmpty({message: "Email không được để trống"})
    name: string;

}