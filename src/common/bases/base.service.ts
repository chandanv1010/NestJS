import { BadRequestException, Injectable, NotFoundException } from "@nestjs/common";
import { Logger } from "@nestjs/common";
import { PrismaService } from "src/modules/prisma/prisma.service";
import { IBaseRepository } from "src/repositories/base.repository";
import { Request } from 'express';
import * as qs from 'qs'
import { IPaginateResult } from "src/classes/query-builder.class";

export type TResult<T> = T | T[] | null | string | number | IPaginateResult<T>

export interface BaseServiceInterface<T, ID = number>{
    save<Q>(payload: Q, id?: ID): Promise<T>,
    show(id: string | number): Promise<T>,
    paginate(request: Request): Promise<T[] | IPaginateResult<T>>
    destroy(id: ID): Promise<T>
}

export type TKeyword = {
    q: string,
    fields: string[]
}
export type TFilterItem = Record<string, string | number | boolean | bigint | Record<string, unknown>>

export interface ISpecifications {
    type: boolean,
    perpage: number,
    page: number
    sort: string,
    keyword:TKeyword,
    filter: {
        simple: TFilterItem ,
        date: TFilterItem,
    }
}

export type TCastField = 'string' | 'number' | 'boolean' | 'bigint'

@Injectable()
export class BaseService<R extends IBaseRepository<TModel, ID>, TModel,  ID = string | number> {
    private readonly logger = new Logger(BaseService.name)

    protected modelData: Partial<TModel>
    protected model: TModel | null
    protected result: TResult<TModel>

    /** ---  */
    protected sort: string = 'id, desc'
    protected perpage: number = 20
    protected searchFields: string[] = ['name']
    protected simpleFilter: string[] = ['publish', 'id']
    protected dateFilter: string[] = ['createdAt', 'updatedAt']
    protected fieldTypes: Record<string, TCastField> = {}

    constructor(
        private readonly repository: R,
        protected readonly prismaService?: PrismaService,
    ){
        
    }

    private buildFilter (query: Record<string, unknown>, filters: string[]): TFilterItem {
        const conditions: TFilterItem = {}
        filters.forEach(filter => {
            if(query[filter] && query[filter] !== undefined ){
                const value = query[filter] as string
                const fieldType = this.fieldTypes[filter]
                if(fieldType){
                    switch (fieldType) {
                        case 'number': {
                            const numValue = parseInt(value, 10)
                            conditions[filter] = numValue
                            break;
                        } 
                        case 'bigint': {
                            try {
                                conditions[filter] = BigInt(value)
                            } catch (error) {
                                console.log('Cast dữ liệu không thành công: ', error);
                                conditions[filter] = value
                            }
                            break
                        }
                        case 'boolean': {
                            conditions[filter] = value === 'true' || value === '1'
                            break;
                        }
                        default:
                            conditions[filter] = value
                            break;
                    }
                }else{
                    conditions[filter] = value
                }
            }
        })
        return conditions 
    }

    private specifications (request: Request): ISpecifications {
        const queryString = request.url.split('?')[1]
        const query = qs.parse(queryString, {depth: 5}) as Record<string, string>

        return {
            type: query.type  === 'all',
            perpage: query.perpage ? parseInt(query.perpage, 10) : this.perpage,
            page: query.page  ? parseInt(query.page) : 1,
            sort: query.sort ?? this.sort,
            keyword: {
                q:  query.keyword ?? null,
                fields: this.searchFields
            },
            filter: {
                simple: this.buildFilter(query, this.simpleFilter),
                date: this.buildFilter(query, this.dateFilter)
            }
        }
    }

    async paginate(request: Request): Promise<IPaginateResult<TModel>>{
        const specifications = this.specifications(request)
        this.result  = await this.repository.pagination(specifications)
        return this.getResult<IPaginateResult<TModel>>()
    }

    async findById(id: ID): Promise<TModel | null>{
        const model = await this.repository.findById(id)
        return model
    }

    async show(id: ID): Promise<TModel>{
        this.result = await this.findById(id)
        return this.getResult<TModel>()
    }

    async save<P>(payload: P, id?: ID): Promise<TModel>{
        if(!this.prismaService){
            throw new BadRequestException("Không thể mở transaction cho tiến trình này")
        }
        return await this.prismaService.$transaction(async() => {
             return await this.prepareModelData<P>(payload)
                .then(() => this.beforeSave(id, payload))
                .then(() => this.saveModel(id))
                .then(() => this.afterSave())
                .then(() => this.handleRelation())
                .then(() => this.getResult<TModel>())
        })
    }


    protected async prepareModelData<P>(payload: P): Promise<this>{
        this.modelData = {...payload} as Partial<TModel>
        return Promise.resolve(this)
    }

    protected async beforeSave(id?: ID, payload?: unknown): Promise<this>{
        console.log('id', id);
        console.log('payload', payload);
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

    async destroy(id: ID): Promise<TModel>{
        if(!this.prismaService){
            throw new BadRequestException("Không thể mở transaction cho tiến trình này")
        }
        return await this.prismaService.$transaction(async() => {
             return await this.beforeDelete(id)
                .then(() => this.deleteModel(id))
                .then(() => this.afterDelete())
                .then(() => this.getResult<TModel>())
        })
    }

    protected async beforeDelete(id: ID): Promise<this>{
        return this.checkModelExist(id)
    }

    private async checkModelExist(id: ID): Promise<this>{
        this.model = await this.findById(id)
        if(!this.model){
            throw new NotFoundException("Không tìm thấy tài nguyên hợp lệ")
        }
        return Promise.resolve(this)
    }

    protected async deleteModel(id: ID): Promise<this>{
        this.result = await this.repository.delete(id)
        return Promise.resolve(this)
    }

    protected async afterDelete(): Promise<this>{
        return Promise.resolve(this)
    }

    protected async getResult<T = TResult<TModel>>(): Promise<T>{
        return Promise.resolve(this.result as T)
    }

   

}