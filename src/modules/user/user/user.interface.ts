export interface User{
    id: bigint,
    email: string,
    password: string,
    name: string,
    phone: string | null,
    createdAt: Date,
    updatedAt: Date
}

export interface IUserResponse {
    id: string,
    email: string,
    name: string,
    phone: string,
    password?: string,
    createdAt: Date,
    updatedAt: Date
}

export type UserWithoutPassword = Omit<User, 'password'>