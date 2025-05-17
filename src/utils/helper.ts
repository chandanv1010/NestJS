export function convertResponse<T extends {id: bigint}>(data: T){
    return {
        ...data,
        id: data.id.toString()
    }
}