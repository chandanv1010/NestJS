import { ValidatorConstraint, ValidatorConstraintInterface, ValidationArguments, registerDecorator, ValidationOptions } from "class-validator";
import {  Injectable, Scope } from "@nestjs/common";
import { PrismaService } from "src/modules/prisma/prisma.service";
import { ModuleRef } from "@nestjs/core";
import { Request } from "express";

@ValidatorConstraint({name: 'IsUnique', async: true})
@Injectable({scope: Scope.REQUEST})
export class IsUniqueConstraint implements ValidatorConstraintInterface {

    constructor(
        private readonly prismaService: PrismaService,
        private readonly moduleRef: ModuleRef
    ){}

    async validate(value: unknown, validationArguments?: ValidationArguments): Promise<boolean> {
        if(!value) return true
        const [ table, field ] = (validationArguments?.constraints as [string, string])  || []
        if(!table || !field) return false
        try {
            const where: Record<string, unknown> = {
                [field]: value
            }


            const httpContext: Request = this.moduleRef.get('REQUEST', { strict: false })
            const request = httpContext.res?.req || httpContext
            console.log('Request: ', request);
            

            const modelId = validationArguments?.object['id'] as unknown
            
            if(modelId){
                where.id = { not: modelId}
            }
            const prismaModel = this.prismaService as unknown as Record<string, unknown>
            const model = prismaModel[table]

            if(!model || typeof model !== 'object'){
                throw new Error(`Model ${table} không hợp lệ`)
            }
            const entity = model as {
                findFirst: (args: { where: Record<string, unknown> }) => Promise<unknown>
            }
            if(typeof entity.findFirst !== 'function'){
                throw new Error(`Không tìm thấy phương thức hợp lệ`)
            }
            const existingRecord = await entity.findFirst({where})
            return !existingRecord
        } catch (error) {
            console.error('Kiểm tra unique thất bại: ', error);
            return false
        }
    }

    defaultMessage(): string {
        return 'Giá trị này đã tồn tại'
    }

}

export function IsUnique(table: string, field: string, validationOptions?: ValidationOptions){
    return function (object: object, propertyName: string){
        registerDecorator({
            target: object.constructor,
            propertyName: propertyName,
            options: validationOptions,
            constraints: [table, field],
            validator: IsUniqueConstraint
        })
    }
}