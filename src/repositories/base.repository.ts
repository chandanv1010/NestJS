import { Injectable } from "@nestjs/common";
import { ISpecifications } from "src/classes/specification-builder.class";
import { IPaginateResult } from "src/classes/query-builder.class";
import { PrismaModel } from "src/classes/query-builder.class";
import { QueryBuilder } from "src/classes/query-builder.class";

export interface IBaseRepository <TModel, ID = string | number> {
    setTransactionClient(tx: unknown): void,
    findById(id: ID): Promise<TModel | null>,
    findByField(field: string, value: string | number): Promise<TModel | null>,
    update<P extends Partial<TModel>>(id: ID, payload: P): Promise<TModel>,
    create<P extends Partial<TModel>>(payload: P): Promise<TModel>,
    delete(id: ID) : Promise<TModel>,
    pagination(specifications: ISpecifications): Promise<TModel[] | IPaginateResult<TModel>>,
    query(): QueryBuilder<TModel>
}

@Injectable()
export class BaseRepository <T extends PrismaModel<TModel>, TModel, ID = number> implements IBaseRepository<TModel, ID>{

    private transactionClient: unknown = null

    constructor(
      protected readonly model: T
    ){
       
    }

    query(): QueryBuilder<TModel>{
        return new QueryBuilder<TModel>(this.model, this.transactionClient)
    }

    setTransactionClient(tx: unknown){
        this.transactionClient = tx
    }
    
    async pagination(specifications: ISpecifications): Promise<TModel[] | IPaginateResult<TModel>> {
        const { type, keyword, sort, perpage, filter, page } = specifications
        const result = await this.query().keyword(keyword).filter(filter.simple).sort(sort).execute(type, page, perpage)
        return result
    }

    async findById(id: ID): Promise<TModel | null> {
        return await this.model.findUnique({
            where: {id}
        })
    }

    async findByField(field: string, value: string | number): Promise<TModel | null> {
        return await this.model.findUnique({
            where: {
                [field]: value
            }
        })
    }

    async update<P extends Partial<TModel>>(id: ID, payload: P): Promise<TModel> {
        return await this.model.update({
            where: { id: id },
            data: payload
        })
    }

    async create<P extends Partial<TModel>>(payload: P): Promise<TModel> {
        return await this.model.create({
            data: payload
        })
    }

    async delete(id: ID): Promise<TModel>{
        return await this.model.delete({
            where: {id: id}
        })
    }



    

}

