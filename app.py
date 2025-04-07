from graphviz import Digraph

# Создаем объект для ER-диаграммы
dot = Digraph('ER Diagram', filename='er_diagram_family_tree', format='png')

# Определяем сущности
dot.node('Person', 'Person\n(person_id, full_name, gender, birth_date,\nbirth_place, residence, occupation, is_alive, comments)')
dot.node('Family', 'Family\n(family_id, husband_id, wife_id)')
dot.node('Relationship', 'Relationship\n(relationship_id, person1_id, person2_id, relation_type)')
dot.node('ChangeLog', 'ChangeLog\n(change_id, change_date, description, person_id)')
dot.node('Location', 'Location\n(location_id, city, country)')

# Определяем связи между сущностями
dot.edge('Family', 'Person', label='husband_id -> person_id')
dot.edge('Family', 'Person', label='wife_id -> person_id')

dot.edge('Relationship', 'Person', label='person1_id -> person_id')
dot.edge('Relationship', 'Person', label='person2_id -> person_id')

dot.edge('ChangeLog', 'Person', label='person_id -> person_id')

dot.edge('Person', 'Location', label='location_id -> location_id')

# Сохраняем диаграмму
dot_path = "/mnt/data/er_diagram_family_tree.png"
dot.render(dot_path, format="png", cleanup=True)

# Выводим изображение
dot_path
