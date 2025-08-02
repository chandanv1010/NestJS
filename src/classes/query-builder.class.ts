// import { TKeyword, TFilterItem } from "src/common/bases/base.service"
import { TKeyword, TFilterItem } from "./specification-builder.class"

export interface IQueryBuilder {
    where?: Record<string, unknown>,
    include?: Record<string, boolean>,
    orderBy?: Record<string, 'asc' | 'desc'> | Record<string, 'asc' | 'desc'>[],
    skip?: number,
    take?: number
}

interface ILink {
    label: string,
    isActive: boolean
}

export interface IPaginateResult<T> {
    data: T[],
    pagination: {
        currentPage: number,
        perpage: number,
        total: number,
        lastPage: number,
        from: number,
        to: number,
        morePage: boolean,
        links?: ILink[]
    }
}

export type PrismaModel<T> = {
    findUnique(args: unknown): Promise<T | null>,
    findMany(args?: unknown): Promise<T[]>,
    create(args: unknown): Promise<T>,
    update(args: unknown): Promise<T>,
    delete(args: unknown): Promise<T>,
    count(args: unknown): Promise<number>
}



export class QueryBuilder <T>{
    private query: IQueryBuilder

    constructor(
        private readonly model: PrismaModel<T>,
        private transactionClient?: unknown
    ){
        this.query = {}
    }

    keyword(
        keyword?: TKeyword
    ): this {
        
        if(!keyword?.q || !keyword.fields.length) return this

        const orLike = keyword.fields.map(field => ({
            [field]: { contains: keyword.q }
        }))

        if(!this.query.where) this.query.where = {} 
        if(Object.keys(this.query.where).length > 0){
            this.query.where = { AND: [this.query.where, { OR: orLike }]}
        }else{
            this.query.where = { OR: orLike }
        }
        return this
    }

    filter(
        filters: TFilterItem
    ): this{
        if(!filters || !Object.keys(filters).length) return this

        if(!this.query.where) this.query.where = {}
        Object.entries(filters).forEach(([key, value]) => {
            if (value !== null && value !== undefined && value !== '') {
                this.query.where![key] = value;
            }
        });
        
        return this
    }

    sort(
        sort?: string
    ){
        if(!sort) return this
        const sorts = sort.split(',').map(s => s.trim())
        const orderBy: Record<string, 'asc' | 'desc'>[] = []
        for(let i = 0; i < sorts.length; i+= 2){
            const field = sorts[i]
            const direction = (sorts[i + 1] || 'asc').toLowerCase() as 'asc' | 'desc'
            if(field){
                orderBy.push({[field]: direction})
            }
        }
        this.query.orderBy = orderBy
        return this
    }

    with(
        relations: Record<string, boolean>
    ): this{
        this.query.include = { ...this.query.include, ...relations }
        return this
    }

    limit(limit: number): this {
        this.query.take = limit
        return this
    }

    offset(offset: number): this {
        this.query.skip = offset
        return this
    }

    async  get(): Promise<T[]> {
        return await this.model.findMany(this.query)
    }

    async count(): Promise<number> {
        const countQuery = {where: this.query.where}
        return await this.model.count(countQuery)
    }

    setPaginate(page: number = 1, perpage: number = 20): this{
        const skip = (page - 1)*perpage

        this.query.take = perpage
        if(skip > 0){
            this.query.skip = skip
        }
        return this
    }

    async paginate(
        page: number = 1,
        perpage: number = 20
    ):Promise<IPaginateResult<T>>{

        const total = await this.count()
        this.setPaginate(page, perpage)

        const data = await this.model.findMany(this.query)

        const lastPage = Math.ceil(total / perpage)
        const from = (page - 1) * perpage + 1
        const to = Math.min(from + data.length - 1, total)

        const links: ILink[] = []
        const maxLinks = 5;
        const rangeStart = Math.max(1, page - Math.floor(maxLinks / 2))
        const rangeEnd = Math.min(lastPage, rangeStart + maxLinks - 1)
        if(page > 1){
            links.push({
                label: 'Trang trước',
                isActive: false
            })
        }

        for(let i = rangeStart; i <= rangeEnd; i++){
            links.push({
                label: i.toString(),
                isActive: i === page
            })
        }

        if(page < lastPage){
            links.push({
                label: 'Trang sau',
                isActive: false
            })
        }

        if(rangeStart > 1){
            links.unshift({
                label: 'Trang đầu',
                isActive: false
            })
        }
        console.log(rangeEnd);
        
        if(rangeEnd < lastPage){
            links.push({
                label: 'Trang cuối',
                isActive: false
            })
        }

        return {
            data,
            pagination: {
                currentPage: page,
                perpage,
                total,
                lastPage,
                from: from > 0 ? 0 : from,
                to: to < 0 ? 0 : to,
                morePage: page < lastPage,
                links
            }
        }
    }

    async execute(type?: boolean, page: number = 1, perpage: number = 20): Promise<T[] | IPaginateResult<T>>{
        if(type){
            return await this.get()
        }
        return await this.paginate(page, perpage)
    }

    getQuery(): IQueryBuilder {
        return this.query
    }

    reset(): this {
        this.query = {}
        return this
    }

}
