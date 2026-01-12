.class public final Landroidx/appcompat/view/menu/qe1;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final a:Ljava/util/TreeMap;

.field public final b:Ljava/util/TreeMap;


# direct methods
.method public constructor <init>()V
    .locals 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Ljava/util/TreeMap;

    invoke-direct {v0}, Ljava/util/TreeMap;-><init>()V

    iput-object v0, p0, Landroidx/appcompat/view/menu/qe1;->a:Ljava/util/TreeMap;

    new-instance v0, Ljava/util/TreeMap;

    invoke-direct {v0}, Ljava/util/TreeMap;-><init>()V

    iput-object v0, p0, Landroidx/appcompat/view/menu/qe1;->b:Ljava/util/TreeMap;

    return-void
.end method

.method public static a(Landroidx/appcompat/view/menu/lw1;Landroidx/appcompat/view/menu/og1;Landroidx/appcompat/view/menu/mg1;)I
    .locals 0

    invoke-static {p2}, Ljava/util/Collections;->singletonList(Ljava/lang/Object;)Ljava/util/List;

    move-result-object p2

    invoke-virtual {p1, p0, p2}, Landroidx/appcompat/view/menu/cg1;->a(Landroidx/appcompat/view/menu/lw1;Ljava/util/List;)Landroidx/appcompat/view/menu/mg1;

    move-result-object p0

    instance-of p1, p0, Landroidx/appcompat/view/menu/uf1;

    if-eqz p1, :cond_0

    invoke-interface {p0}, Landroidx/appcompat/view/menu/mg1;->f()Ljava/lang/Double;

    move-result-object p0

    invoke-virtual {p0}, Ljava/lang/Double;->doubleValue()D

    move-result-wide p0

    invoke-static {p0, p1}, Landroidx/appcompat/view/menu/eu1;->i(D)I

    move-result p0

    return p0

    :cond_0
    const/4 p0, -0x1

    return p0
.end method


# virtual methods
.method public final b(Landroidx/appcompat/view/menu/lw1;Landroidx/appcompat/view/menu/ye1;)V
    .locals 5

    new-instance v0, Landroidx/appcompat/view/menu/j92;

    invoke-direct {v0, p2}, Landroidx/appcompat/view/menu/j92;-><init>(Landroidx/appcompat/view/menu/ye1;)V

    iget-object v1, p0, Landroidx/appcompat/view/menu/qe1;->a:Ljava/util/TreeMap;

    invoke-virtual {v1}, Ljava/util/TreeMap;->keySet()Ljava/util/Set;

    move-result-object v1

    invoke-interface {v1}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    move-result-object v1

    :cond_0
    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_2

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/lang/Integer;

    invoke-virtual {p2}, Landroidx/appcompat/view/menu/ye1;->d()Landroidx/appcompat/view/menu/df1;

    move-result-object v3

    invoke-virtual {v3}, Landroidx/appcompat/view/menu/df1;->clone()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Landroidx/appcompat/view/menu/df1;

    iget-object v4, p0, Landroidx/appcompat/view/menu/qe1;->a:Ljava/util/TreeMap;

    invoke-virtual {v4, v2}, Ljava/util/TreeMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Landroidx/appcompat/view/menu/og1;

    invoke-static {p1, v2, v0}, Landroidx/appcompat/view/menu/qe1;->a(Landroidx/appcompat/view/menu/lw1;Landroidx/appcompat/view/menu/og1;Landroidx/appcompat/view/menu/mg1;)I

    move-result v2

    const/4 v4, 0x2

    if-eq v2, v4, :cond_1

    const/4 v4, -0x1

    if-ne v2, v4, :cond_0

    :cond_1
    invoke-virtual {p2, v3}, Landroidx/appcompat/view/menu/ye1;->e(Landroidx/appcompat/view/menu/df1;)V

    goto :goto_0

    :cond_2
    iget-object p2, p0, Landroidx/appcompat/view/menu/qe1;->b:Ljava/util/TreeMap;

    invoke-virtual {p2}, Ljava/util/TreeMap;->keySet()Ljava/util/Set;

    move-result-object p2

    invoke-interface {p2}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    move-result-object p2

    :goto_1
    invoke-interface {p2}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_3

    invoke-interface {p2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/Integer;

    iget-object v2, p0, Landroidx/appcompat/view/menu/qe1;->b:Ljava/util/TreeMap;

    invoke-virtual {v2, v1}, Ljava/util/TreeMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Landroidx/appcompat/view/menu/og1;

    invoke-static {p1, v1, v0}, Landroidx/appcompat/view/menu/qe1;->a(Landroidx/appcompat/view/menu/lw1;Landroidx/appcompat/view/menu/og1;Landroidx/appcompat/view/menu/mg1;)I

    goto :goto_1

    :cond_3
    return-void
.end method

.method public final c(Ljava/lang/String;ILandroidx/appcompat/view/menu/og1;Ljava/lang/String;)V
    .locals 0

    const-string p1, "create"

    invoke-virtual {p1, p4}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_0

    iget-object p1, p0, Landroidx/appcompat/view/menu/qe1;->b:Ljava/util/TreeMap;

    goto :goto_0

    :cond_0
    const-string p1, "edit"

    invoke-virtual {p1, p4}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_2

    iget-object p1, p0, Landroidx/appcompat/view/menu/qe1;->a:Ljava/util/TreeMap;

    :goto_0
    invoke-static {p2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p4

    invoke-virtual {p1, p4}, Ljava/util/TreeMap;->containsKey(Ljava/lang/Object;)Z

    move-result p4

    if-eqz p4, :cond_1

    invoke-virtual {p1}, Ljava/util/TreeMap;->lastKey()Ljava/lang/Object;

    move-result-object p2

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    move-result p2

    add-int/lit8 p2, p2, 0x1

    :cond_1
    invoke-static {p2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p2

    invoke-virtual {p1, p2, p3}, Ljava/util/TreeMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    return-void

    :cond_2
    new-instance p1, Ljava/lang/IllegalStateException;

    new-instance p2, Ljava/lang/StringBuilder;

    const-string p3, "Unknown callback type: "

    invoke-direct {p2, p3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p2, p4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p2

    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method
