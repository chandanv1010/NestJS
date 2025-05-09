import { Injectable } from "@nestjs/common";
import { Logger } from "@nestjs/common";
import { IBaseRepository } from "src/repositories/base.repository";

@Injectable()
export class BaseService<R extends IBaseRepository<TModel, ID>, TModel, ID = number> {
    private readonly logger = new Logger(BaseService.name)


    constructor(
        private readonly repository: R,
    ){
        
    }

    async show(id: string | number): Promise<TModel | null>{
        const model = await this.repository.findById(id as ID)
        return model
    }

}