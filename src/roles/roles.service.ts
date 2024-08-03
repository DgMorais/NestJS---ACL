import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { CreateRoleDto } from './dto/create-role.dto';
import { UpdateRoleDto } from './dto/update-role.dto';
import { Role } from './entities/role.entity';
import { Permission } from '../permissions/entities/permission.entity';

@Injectable()
export class RolesService {
    constructor(
        @InjectRepository(Role)
        private readonly rolesRepository: Repository<Role>,
        @InjectRepository(Permission)
        private readonly permissionsRepository: Repository<Permission>,
    ) { }

    /**
     * Cria um novo role.
     * @param createRoleDto Detalhes do role a ser criado.
     * @returns O role criado.
     */
    async create(createRoleDto: CreateRoleDto): Promise<Role> {
        const permissions = await this.permissionsRepository.findByIds(createRoleDto.permissionIds ?? []);
        const role = this.rolesRepository.create({ ...createRoleDto, permissions });
        return this.rolesRepository.save(role);
    }

    /**
     * Obtém todos os roles.
     * @returns Uma lista de todos os roles.
     */
    findAll(): Promise<Role[]> {
        return this.rolesRepository.find({ relations: ['permissions'] });
    }

    /**
     * Obtém um role pelo ID.
     * @param id O ID do role.
     * @returns O role correspondente ao ID.
     */
    async findOne(id: number): Promise<Role> {
        const role = await this.rolesRepository.findOne({ where: { id }, relations: ['permissions'] });
        if (!role) {
            throw new NotFoundException('Role não encontrado');
        }
        return role;
    }

    /**
     * Atualiza um role.
     * @param id O ID do role a ser atualizado.
     * @param updateRoleDto Os novos detalhes do role.
     * @returns O role atualizado.
     */
    async update(id: number, updateRoleDto: UpdateRoleDto): Promise<Role> {
        const permissions = await this.permissionsRepository.findByIds(updateRoleDto.permissionIds ?? []);
        await this.rolesRepository.update(id, { ...updateRoleDto, permissions });
        return this.findOne(id);
    }

    /**
     * Remove um role.
     * @param id O ID do role a ser removido.
     */
    async remove(id: number): Promise<void> {
        const role = await this.findOne(id);
        if (!role) {
            throw new NotFoundException('Role não encontrado');
        }
        await this.rolesRepository.delete(id);
    }
}
