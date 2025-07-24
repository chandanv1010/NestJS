import { Injectable } from "@nestjs/common";
import { ClassConstructor, plainToClass } from "class-transformer";
import { IPaginateResult } from "src/classes/query-builder.class";
import { TResult } from "./base.service";

export interface IDataTransformer<TModel, ResponseDTO> {
    transform(data: TResult<TModel>, dto?: ClassConstructor<ResponseDTO>): null | string | number | ResponseDTO | ResponseDTO[] | IPaginateResult<ResponseDTO> | TModel | TModel[] | IPaginateResult<TModel>;
}

@Injectable()
export class DataTransformer<TModel, ResponseDTO> implements IDataTransformer<TModel, ResponseDTO> {

    
    transform<R = ResponseDTO>(data: TResult<TModel>, dto?: ClassConstructor<R>): null | string | number | TModel | R | TModel[] | IPaginateResult<TModel> | R[] | IPaginateResult<R> {
        
        const dataTransformBigInt = data

        if(!dataTransformBigInt) return null

        if(!dto){
            return dataTransformBigInt 
        }
        if(Array.isArray(dataTransformBigInt)){
            return dataTransformBigInt.map(item => 
                plainToClass(dto, item, {excludeExtraneousValues: true})
            ) 

        }
        if(dataTransformBigInt && typeof dataTransformBigInt === 'object' && 'data' in dataTransformBigInt && 'pagination' in dataTransformBigInt){
            const paginatedResult = dataTransformBigInt as unknown as IPaginateResult<TModel>
            return {
                data: paginatedResult.data.map(item => 
                    plainToClass(dto, item, {excludeExtraneousValues: true})
                ),
                pagination: paginatedResult.pagination
            }
        }

        return plainToClass(dto, dataTransformBigInt, {excludeExtraneousValues: true})
    }


    transformSingle(data: TModel, dto: ClassConstructor<ResponseDTO>): ResponseDTO {
        if(!data){
            throw new Error('Data không hợp lệ')
        }
        return plainToClass(dto, data, {excludeExtraneousValues: true})
    }

    transformArray(data: TModel[], dto: ClassConstructor<ResponseDTO>): ResponseDTO[] {
        if(!data){
            throw new Error('Data không hợp lệ')
        }
        return data.map(item => plainToClass(dto, item, {excludeExtraneousValues: true}))
    }

    transformPaginated(data: IPaginateResult<TModel>, dto: ClassConstructor<ResponseDTO>): IPaginateResult<ResponseDTO> {
        if(!data || !data.data || !data.pagination){
            throw new Error('Data không hợp lệ')
        }
        return {
            data: data.data.map(item => plainToClass(dto, item, {excludeExtraneousValues: true})),
            pagination: data.pagination
        }
    }

}