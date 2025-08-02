import { Injectable, Logger } from "@nestjs/common";
import * as qs from 'qs'
import { Request } from 'express';

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
export class SpecificationBuilder {
    private readonly logger = new Logger(SpecificationBuilder.name)

    /** ---  */
    protected sort: string = 'id, desc'
    protected perpage: number = 20
    protected searchFields: string[] = ['name']
    protected simpleFilter: string[] = ['publish', 'id']
    protected dateFilter: string[] = ['createdAt', 'updatedAt']
    protected fieldTypes: Record<string, TCastField> = {}


    buildFilter (query: Record<string, unknown>, filters: string[]): TFilterItem {
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

    
    buildSpecifications (request: Request): ISpecifications {
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

}