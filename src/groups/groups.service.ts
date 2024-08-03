import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { CreateGroupDto } from './dto/create-group.dto';
import { UpdateGroupDto } from './dto/update-group.dto';
import { Group } from './entities/group.entity';
import { Role } from '../roles/entities/role.entity';

@Injectable()
export class GroupsService {
    constructor(
        @InjectRepository(Group)
        private readonly groupRepository: Repository<Group>,
        @InjectRepository(Role)
        private readonly roleRepository: Repository<Role>,
    ) { }

    /**
     * Cria um novo grupo.
     * @param createGroupDto Detalhes do grupo a ser criado.
     * @returns O grupo criado.
     */
    async create(createGroupDto: CreateGroupDto): Promise<Group> {
        const roles = await this.roleRepository.findByIds(createGroupDto.roleIds ?? []);
        const group = this.groupRepository.create({ ...createGroupDto, roles });
        return this.groupRepository.save(group);
    }

    /**
     * Obtém todos os grupos.
     * @returns Uma lista de todos os grupos.
     */
    findAll(): Promise<Group[]> {
        return this.groupRepository.find({ relations: ['roles', 'users'] });
    }

    /**
     * Obtém um grupo pelo ID.
     * @param id O ID do grupo.
     * @returns O grupo correspondente ao ID.
     */
    async findOne(id: number): Promise<Group> {
        const group = await this.groupRepository.findOne({ where: { id }, relations: ['roles', 'users'] });
        if (!group) {
            throw new NotFoundException('Grupo não encontrado');
        }
        return group;
    }

    /**
     * Atualiza um grupo.
     * @param id O ID do grupo a ser atualizado.
     * @param updateGroupDto Os novos detalhes do grupo.
     * @returns O grupo atualizado.
     */
    async update(id: number, updateGroupDto: UpdateGroupDto): Promise<Group> {
        const roles = await this.roleRepository.findByIds(updateGroupDto.roleIds ?? []);
        await this.groupRepository.update(id, { ...updateGroupDto, roles });
        return this.findOne(id);
    }

    /**
     * Remove um grupo.
     * @param id O ID do grupo a ser removido.
     */
    async remove(id: number): Promise<void> {
        const group = await this.findOne(id);
        if (!group) {
            throw new NotFoundException('Grupo não encontrado');
        }
        await this.groupRepository.delete(id);
    }

    async findByName(name: string): Promise<Group> {
        const group = await this.groupRepository.findOne({ where: { name }, relations: ['roles', 'users'] });
        if (!group) {
            throw new NotFoundException(`Group with name ${name} not found`);
        }
        return group;
    }   
}
