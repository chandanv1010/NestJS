export interface User{
    id: bigint,
    name: string,
    canonical: string,
    publish: number,
    createdAt: Date,
    updatedAt: Date
}

export interface IUserCatalogueResponse {
    id: string,
    name: string,
    canonical: string,
    publish: number,
}