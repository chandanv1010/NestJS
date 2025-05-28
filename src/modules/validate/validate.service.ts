import { BadRequestException, Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { Logger } from '@nestjs/common';

interface IValidationContext {
    id?: number
    [key: string] : unknown
}
interface IValidationOption {
    message?: string
}

interface ICheckValidation {
    type: TCheckType,
    field: string,
    value: IValidationValue,
    model?: keyof PrismaService,
    message?: string
}

type TCheckType = 'unique'

type IValidationValue = string | number

@Injectable()
export class ValidateService {
    
    private readonly logger = new Logger(ValidateService.name)

    private modelName: string
    private initialContext: IValidationContext = {}
    private check: ICheckValidation[] = []

    constructor(
        protected readonly prismaService: PrismaService
    ){}

    model(modelName: string): this {
       this.modelName = modelName
       this.initialContext = {}
       this.check = []
       return this
    }

    context(initialContext: IValidationContext): this{
        this.initialContext = initialContext
        return this
    }

    private setRule(type: TCheckType, field: string, value: IValidationValue, options: IValidationOption = {}): this{
        this.check.push({type, field, value, ...options})
        return this
    }

    unique(field: string, value: IValidationValue, message?: string): this{
        return this.setRule('unique', field, value, { message })
    }

    // exists(field: string, value: IValidationValue, message?: string){
    //     this.setRule('exists', field, value, { message })
    // }

    private handler: Record<TCheckType, (checkRule: ICheckValidation) => Promise<void>> = {
        unique: this.handlerUnique.bind(this) as (checkRule: ICheckValidation) => Promise<void>,
    }  

    async validate(){
        for(const check of this.check){
            const handler = this.handler[check.type]
            if(!handler) throw new Error(`Không tìm thấy hàm validate hàm lệ: ${check.type}`)
            await handler(check)
        }
    }

    private async handlerUnique(check: ICheckValidation){
        const prismaModel = this.prismaService as unknown as Record<string, unknown>
        const model = prismaModel[this.modelName]
        
        if(!model || typeof model !== 'object'){
            throw new Error(`Model ${this.modelName} không hợp lệ`)
        }
        const where: Record<string, unknown> = {
            [check.field]: check.value
        }
        
        const entity = model as {
            findFirst: (args: { where: Record<string, unknown> }) => Promise<unknown>
        }
        if(this.initialContext.id){
            where.id = { not: this.initialContext.id}
        }
        if(typeof entity.findFirst !== 'function'){
            throw new Error(`Không tìm thấy phương thức hợp lệ`)
        }
        const existingRecord = await entity.findFirst({where})
        if(existingRecord){
            throw new BadRequestException(check.message || `${check.field} đã tồn tại`)
        }
    }
    
}

