
import { IsString, IsNotEmpty, IsIn, IsNumber } from "class-validator";


export class StoreRequest {

    @IsString({message: "Tên nhóm thành viên phải là kiểu chuỗi"})
    @IsNotEmpty({message: "Tên nhóm thành viên không được để trống"})
    name: string;

    @IsString({message: 'Canonical phải là chuỗi'})
    @IsNotEmpty({message: 'Canonical không được để trống'})
    canonical: string

    @IsNumber({}, {message: 'Trạng thái phải là dạng số'})
    @IsIn([1,2], {message: 'Giá trị của Publish là 1 hoặc 2'})
    @IsNotEmpty({message: 'Trạng thái không được để trống'})
    publish: number
}