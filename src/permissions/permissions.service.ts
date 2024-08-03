import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { CreatePermissionDto } from './dto/create-permission.dto';
import { UpdatePermissionDto } from './dto/update-permission.dto';
import { Permission } from './entities/permission.entity';

@Injectable()
export class PermissionsService {
    constructor(
        @InjectRepository(Permission)
        private readonly permissionsRepository: Repository<Permission>,
    ) { }

    /**
     * Cria uma nova permissão.
     * @param createPermissionDto Detalhes da permissão a ser criada.
     * @returns A permissão criada.
     */
    create(createPermissionDto: CreatePermissionDto): Promise<Permission> {
        const permission = this.permissionsRepository.create(createPermissionDto);
        return this.permissionsRepository.save(permission);
    }

    /**
     * Obtém todas as permissões.
     * @returns Uma lista de todas as permissões.
     */
    findAll(): Promise<Permission[]> {
        return this.permissionsRepository.find();
    }

    /**
     * Obtém uma permissão pelo ID.
     * @param id O ID da permissão.
     * @returns A permissão correspondente ao ID.
     */
    async findOne(id: number): Promise<Permission> {
        const permission = await this.permissionsRepository.findOne({ where: { id } });
        if (!permission) {
            throw new NotFoundException('Permissão não encontrada');
        }
        return permission;
    }

    /**
     * Atualiza uma permissão.
     * @param id O ID da permissão a ser atualizada.
     * @param updatePermissionDto Os novos detalhes da permissão.
     * @returns A permissão atualizada.
     */
    async update(id: number, updatePermissionDto: UpdatePermissionDto): Promise<Permission> {
        await this.permissionsRepository.update(id, updatePermissionDto);
        return this.findOne(id);
    }

    /**
     * Remove uma permissão.
     * @param id O ID da permissão a ser removida.
     */
    async remove(id: number): Promise<void> {
        const permission = await this.findOne(id);
        if (!permission) {
            throw new NotFoundException('Permissão não encontrada');
        }
        await this.permissionsRepository.delete(id);
    }
}
