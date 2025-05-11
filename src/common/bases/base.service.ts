import { BadRequestException, Injectable } from "@nestjs/common";
import { Logger } from "@nestjs/common";
import { IBaseRepository } from "src/repositories/base.repository";
import { PrismaService } from "src/modules/prisma/prisma.service";


type TResult<T> = T | T[] | null | string | number
@Injectable()
export class BaseService<R extends IBaseRepository<TModel, ID>, TModel, ID = number> {
    private readonly logger = new Logger(BaseService.name)

    protected modelData: Partial<TModel>
    protected model: TModel
    protected result: TResult<TModel>



    constructor(
        private readonly repository: R,
        private readonly prismaService?: PrismaService,
    ){
        
    }

    async show(id: string | number): Promise<TModel | null>{
        const model = await this.repository.findById(id as ID)
        return model
    }

    async save<P>(payload: P, id?: ID): Promise<TResult<TModel>>{

        if(!this.prismaService){
            throw new BadRequestException("Không thể mở transaction cho tiến trình này")
        }

        return await this.prismaService?.$transaction(async() => {
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

    protected async getResult(): Promise<TResult<TModel>>{
        return Promise.resolve(this.result)
    }

}