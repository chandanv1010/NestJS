import { BadRequestException, Injectable } from "@nestjs/common";
import { Logger } from "@nestjs/common";
import { PrismaService } from "src/modules/prisma/prisma.service";
import { IBaseRepository } from "src/repositories/base.repository";
import { ClassConstructor, plainToClass } from "class-transformer";

export type TResult<T, R> = T | T[] | R | R[] | null | string | number

export interface BaseServiceInterface<C, U, T, R, ID = number>{
    save<Q = C | U>(payload: Q, id?: ID): Promise<TResult<T, R>>
    show(id: string | number): Promise<TResult<T, R>>
}

@Injectable()
export class BaseService<R extends IBaseRepository<TModel, ID>, TModel, ResponseDTO, ID = number> {
    private readonly logger = new Logger(BaseService.name)

    protected modelData: Partial<TModel>
    protected model: TModel
    protected result: TResult<TModel, ResponseDTO>

    constructor(
        private readonly repository: R,
        protected readonly prismaService?: PrismaService,
        protected readonly dto: ClassConstructor<ResponseDTO> | null = null
    ){
        
    }

    async findById(id: string | number): Promise<TModel | null>{
        const model = await this.repository.findById(id as ID)
        return model
    }

    async show(id: string | number): Promise<TResult<TModel, ResponseDTO>>{
        this.result = await this.findById(id)
        return this.getResult()
    }

    async save<P>(payload: P, id?: ID): Promise<TResult<TModel, ResponseDTO>>{
        if(!this.prismaService){
            throw new BadRequestException("Không thể mở transaction cho tiến trình này")
        }

        return await this.prismaService.$transaction(async() => {
             return await this.prepareModelData<P>(payload)
                .then(() => this.beforeSave())
                .then(() => this.saveModel(id))
                .then(() => this.afterSave())
                .then(() => this.handleRelation())
                .then(() => this.getResult())
        })
    }


    protected async prepareModelData<P>(payload: P): Promise<this>{
        this.modelData = {...payload} as Partial<TModel>
        return Promise.resolve(this)
    }

    protected async beforeSave(): Promise<this>{
        return Promise.resolve(this)
    }

    protected async afterSave(): Promise<this>{
        return Promise.resolve(this)
    }

    protected async handleRelation(): Promise<this> {
        return Promise.resolve(this)
    }

    protected async saveModel(id?: ID): Promise<this> {
        if(id){
            this.model = await this.repository.update(id, this.modelData)
        }else{
            this.model = await this.repository.create(this.modelData)
        }
        this.result = this.model
        return this
    }

    protected async getResult(): Promise<TResult<TModel, ResponseDTO>>{
        if(this.result === null || typeof this.result === 'string' || typeof this.result === 'number' || typeof this.result === 'boolean'){
            return Promise.resolve(this.result)
        }
        if(Array.isArray(this.result)){
            if(this.dto){
                const transformItems = this.result.map(item =>
                    plainToClass(this.dto as ClassConstructor<ResponseDTO>, item, {
                        excludeExtraneousValues: true
                    })
                )
                return Promise.resolve(transformItems)
            }
            return Promise.resolve(this.result as unknown as ResponseDTO[])
        }
        if(this.dto){
            console.log(123);
            
            return Promise.resolve(
                plainToClass(this.dto, this.result, {
                    excludeExtraneousValues: true
                })
            )
        }

        return Promise.resolve(this.result as unknown as ResponseDTO)
    }

}