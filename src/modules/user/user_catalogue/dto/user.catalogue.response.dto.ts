import { Expose, Transform, TransformFnParams } from "class-transformer";

export class UserCatalogueDTO {

    @Expose()
    @Transform(val => String(val.value))
    id: bigint

    @Expose()
    name: string

    @Expose()
    canonical: string

    @Expose()
    publish: number

    @Expose()
    @Transform(({ value }: TransformFnParams) => value ? new Date(value as string | number | Date).toISOString() : null)
    createdAt: Date

    @Expose()
    @Transform(({ value }: TransformFnParams) => value ? new Date(value as string | number | Date).toISOString() : null)
    updatedAt: Date
}