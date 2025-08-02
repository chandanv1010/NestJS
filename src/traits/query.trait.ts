import { TKeyword, TFilterItem } from "src/classes/specification-builder.class"

export interface IQueryBuilder {
    where?: Record<string, unknown>,
    include?: Record<string, boolean>,
    orderBy?: Record<string, 'asc' | 'desc'> | Record<string, 'asc' | 'desc'>[],
    skip?: number,
    take?: number
}

export const HasQuery = {

    keyword(
        query: IQueryBuilder,
        keyword?: TKeyword
    ): IQueryBuilder {
        
        if(!keyword?.q || !keyword.fields.length) return query

        const orLike = keyword.fields.map(field => ({
            [field]: { contains: keyword.q, mode: 'intensive' }
        }))

        if(!query.where) query.where = {}
        if(Object.keys(query.where).length > 0){
            query.where = { AND: [query.where, { OR: orLike }]}
        }else{
            query.where = { OR: orLike }
        }
        return query
    },

    simpleFilter(
        query: IQueryBuilder,
        filters: TFilterItem
    ): IQueryBuilder{
        if(!filters || !Object.keys(filters).length) return query

        if(!query.where) query.where = {}
        Object.entries(filters).forEach(([key, value]) => {
            if (value !== null && value !== undefined && value !== '') {
                query.where![key] = value;
            }
        });
        return query
    }

}
