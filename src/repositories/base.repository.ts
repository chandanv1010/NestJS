import { Injectable } from "@nestjs/common";

type PrismaModel<TModel> = {
    findUnique(args: unknown): Promise<TModel | null>,
    findMany(args?: unknown): Promise<TModel[]>,
    create(args: unknown): Promise<TModel>,
    update(args: unknown): Promise<TModel>,
    delete(args: unknown): Promise<TModel>
}

export interface IBaseRepository <TModel, ID = number> {
    setTransactionClient(tx: unknown): void,
    findById(id: ID): Promise<TModel | null>,
    findByField(field: string, value: string | number): Promise<TModel | null>,
    update<P extends Partial<TModel>>(id: ID, payload: P): Promise<TModel>,
    create<P extends Partial<TModel>>(payload: P): Promise<TModel>
}

@Injectable()
export class BaseRepository <T extends PrismaModel<TModel>, TModel, ID = number> implements IBaseRepository<TModel, ID>{

    private transactionClient: unknown = null

    constructor(
      protected readonly model: T
    ){
       
    }

    setTransactionClient(tx: unknown){
        this.transactionClient = tx
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



    

}

