.class public final Landroidx/appcompat/view/menu/li1;
.super Landroidx/appcompat/view/menu/ch1;
.source "SourceFile"


# direct methods
.method public constructor <init>()V
    .locals 2

    invoke-direct {p0}, Landroidx/appcompat/view/menu/ch1;-><init>()V

    iget-object v0, p0, Landroidx/appcompat/view/menu/ch1;->a:Ljava/util/List;

    sget-object v1, Landroidx/appcompat/view/menu/pj1;->o:Landroidx/appcompat/view/menu/pj1;

    invoke-interface {v0, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    iget-object v0, p0, Landroidx/appcompat/view/menu/ch1;->a:Ljava/util/List;

    sget-object v1, Landroidx/appcompat/view/menu/pj1;->i0:Landroidx/appcompat/view/menu/pj1;

    invoke-interface {v0, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    iget-object v0, p0, Landroidx/appcompat/view/menu/ch1;->a:Ljava/util/List;

    sget-object v1, Landroidx/appcompat/view/menu/pj1;->l0:Landroidx/appcompat/view/menu/pj1;

    invoke-interface {v0, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    return-void
.end method


# virtual methods
.method public final b(Ljava/lang/String;Landroidx/appcompat/view/menu/lw1;Ljava/util/List;)Landroidx/appcompat/view/menu/mg1;
    .locals 5

    sget-object v0, Landroidx/appcompat/view/menu/ri1;->a:[I

    invoke-static {p1}, Landroidx/appcompat/view/menu/eu1;->c(Ljava/lang/String;)Landroidx/appcompat/view/menu/pj1;

    move-result-object v1

    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    move-result v1

    aget v0, v0, v1

    const/4 v1, 0x0

    const/4 v2, 0x2

    const/4 v3, 0x1

    if-eq v0, v3, :cond_3

    if-eq v0, v2, :cond_2

    const/4 v4, 0x3

    if-eq v0, v4, :cond_0

    invoke-super {p0, p1}, Landroidx/appcompat/view/menu/ch1;->a(Ljava/lang/String;)Landroidx/appcompat/view/menu/mg1;

    move-result-object p1

    return-object p1

    :cond_0
    sget-object p1, Landroidx/appcompat/view/menu/pj1;->l0:Landroidx/appcompat/view/menu/pj1;

    invoke-static {p1, v2, p3}, Landroidx/appcompat/view/menu/eu1;->f(Landroidx/appcompat/view/menu/pj1;ILjava/util/List;)V

    invoke-interface {p3, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Landroidx/appcompat/view/menu/mg1;

    invoke-virtual {p2, p1}, Landroidx/appcompat/view/menu/lw1;->b(Landroidx/appcompat/view/menu/mg1;)Landroidx/appcompat/view/menu/mg1;

    move-result-object p1

    invoke-interface {p1}, Landroidx/appcompat/view/menu/mg1;->d()Ljava/lang/Boolean;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v0

    if-eqz v0, :cond_1

    return-object p1

    :cond_1
    invoke-interface {p3, v3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Landroidx/appcompat/view/menu/mg1;

    invoke-virtual {p2, p1}, Landroidx/appcompat/view/menu/lw1;->b(Landroidx/appcompat/view/menu/mg1;)Landroidx/appcompat/view/menu/mg1;

    move-result-object p1

    return-object p1

    :cond_2
    sget-object p1, Landroidx/appcompat/view/menu/pj1;->i0:Landroidx/appcompat/view/menu/pj1;

    invoke-static {p1, v3, p3}, Landroidx/appcompat/view/menu/eu1;->f(Landroidx/appcompat/view/menu/pj1;ILjava/util/List;)V

    invoke-interface {p3, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Landroidx/appcompat/view/menu/mg1;

    invoke-virtual {p2, p1}, Landroidx/appcompat/view/menu/lw1;->b(Landroidx/appcompat/view/menu/mg1;)Landroidx/appcompat/view/menu/mg1;

    move-result-object p1

    new-instance p2, Landroidx/appcompat/view/menu/of1;

    invoke-interface {p1}, Landroidx/appcompat/view/menu/mg1;->d()Ljava/lang/Boolean;

    move-result-object p1

    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    move-result p1

    xor-int/2addr p1, v3

    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object p1

    invoke-direct {p2, p1}, Landroidx/appcompat/view/menu/of1;-><init>(Ljava/lang/Boolean;)V

    return-object p2

    :cond_3
    sget-object p1, Landroidx/appcompat/view/menu/pj1;->o:Landroidx/appcompat/view/menu/pj1;

    invoke-static {p1, v2, p3}, Landroidx/appcompat/view/menu/eu1;->f(Landroidx/appcompat/view/menu/pj1;ILjava/util/List;)V

    invoke-interface {p3, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Landroidx/appcompat/view/menu/mg1;

    invoke-virtual {p2, p1}, Landroidx/appcompat/view/menu/lw1;->b(Landroidx/appcompat/view/menu/mg1;)Landroidx/appcompat/view/menu/mg1;

    move-result-object p1

    invoke-interface {p1}, Landroidx/appcompat/view/menu/mg1;->d()Ljava/lang/Boolean;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v0

    if-nez v0, :cond_4

    return-object p1

    :cond_4
    invoke-interface {p3, v3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Landroidx/appcompat/view/menu/mg1;

    invoke-virtual {p2, p1}, Landroidx/appcompat/view/menu/lw1;->b(Landroidx/appcompat/view/menu/mg1;)Landroidx/appcompat/view/menu/mg1;

    move-result-object p1

    return-object p1
.end method
