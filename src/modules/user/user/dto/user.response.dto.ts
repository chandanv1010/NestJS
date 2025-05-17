import { Expose, Transform, TransformFnParams } from "class-transformer";

export class UserDto {

    @Expose()
    @Transform(val => String(val.value))
    id: string

    @Expose()
    email: string

    @Expose()
    name: string

    @Expose()
    phone: string

    @Expose()
    @Transform(({ value }: TransformFnParams) => value ? new Date(value as string | number | Date).toISOString() : null)
    createdAt: Date

    @Expose()
    @Transform(({ value }: TransformFnParams) => value ? new Date(value as string | number | Date).toISOString() : null)
    updatedAt: Date
}