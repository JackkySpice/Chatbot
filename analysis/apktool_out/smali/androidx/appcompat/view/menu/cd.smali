.class public final Landroidx/appcompat/view/menu/cd;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroidx/appcompat/view/menu/jh;
.implements Ljava/io/Serializable;


# instance fields
.field public final m:Landroidx/appcompat/view/menu/jh;

.field public final n:Landroidx/appcompat/view/menu/jh$b;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/jh;Landroidx/appcompat/view/menu/jh$b;)V
    .locals 1

    const-string v0, "left"

    invoke-static {p1, v0}, Landroidx/appcompat/view/menu/x50;->e(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "element"

    invoke-static {p2, v0}, Landroidx/appcompat/view/menu/x50;->e(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Landroidx/appcompat/view/menu/cd;->m:Landroidx/appcompat/view/menu/jh;

    iput-object p2, p0, Landroidx/appcompat/view/menu/cd;->n:Landroidx/appcompat/view/menu/jh$b;

    return-void
.end method


# virtual methods
.method public final b(Landroidx/appcompat/view/menu/jh$b;)Z
    .locals 1

    invoke-interface {p1}, Landroidx/appcompat/view/menu/jh$b;->getKey()Landroidx/appcompat/view/menu/jh$c;

    move-result-object v0

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/cd;->d(Landroidx/appcompat/view/menu/jh$c;)Landroidx/appcompat/view/menu/jh$b;

    move-result-object v0

    invoke-static {v0, p1}, Landroidx/appcompat/view/menu/x50;->a(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p1

    return p1
.end method

.method public d(Landroidx/appcompat/view/menu/jh$c;)Landroidx/appcompat/view/menu/jh$b;
    .locals 2

    const-string v0, "key"

    invoke-static {p1, v0}, Landroidx/appcompat/view/menu/x50;->e(Ljava/lang/Object;Ljava/lang/String;)V

    move-object v0, p0

    :goto_0
    iget-object v1, v0, Landroidx/appcompat/view/menu/cd;->n:Landroidx/appcompat/view/menu/jh$b;

    invoke-interface {v1, p1}, Landroidx/appcompat/view/menu/jh$b;->d(Landroidx/appcompat/view/menu/jh$c;)Landroidx/appcompat/view/menu/jh$b;

    move-result-object v1

    if-eqz v1, :cond_0

    return-object v1

    :cond_0
    iget-object v0, v0, Landroidx/appcompat/view/menu/cd;->m:Landroidx/appcompat/view/menu/jh;

    instance-of v1, v0, Landroidx/appcompat/view/menu/cd;

    if-eqz v1, :cond_1

    check-cast v0, Landroidx/appcompat/view/menu/cd;

    goto :goto_0

    :cond_1
    invoke-interface {v0, p1}, Landroidx/appcompat/view/menu/jh;->d(Landroidx/appcompat/view/menu/jh$c;)Landroidx/appcompat/view/menu/jh$b;

    move-result-object p1

    return-object p1
.end method

.method public equals(Ljava/lang/Object;)Z
    .locals 2

    if-eq p0, p1, :cond_1

    instance-of v0, p1, Landroidx/appcompat/view/menu/cd;

    if-eqz v0, :cond_0

    check-cast p1, Landroidx/appcompat/view/menu/cd;

    invoke-virtual {p1}, Landroidx/appcompat/view/menu/cd;->g()I

    move-result v0

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/cd;->g()I

    move-result v1

    if-ne v0, v1, :cond_0

    invoke-virtual {p1, p0}, Landroidx/appcompat/view/menu/cd;->f(Landroidx/appcompat/view/menu/cd;)Z

    move-result p1

    if-eqz p1, :cond_0

    goto :goto_0

    :cond_0
    const/4 p1, 0x0

    goto :goto_1

    :cond_1
    :goto_0
    const/4 p1, 0x1

    :goto_1
    return p1
.end method

.method public final f(Landroidx/appcompat/view/menu/cd;)Z
    .locals 1

    :goto_0
    iget-object v0, p1, Landroidx/appcompat/view/menu/cd;->n:Landroidx/appcompat/view/menu/jh$b;

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/cd;->b(Landroidx/appcompat/view/menu/jh$b;)Z

    move-result v0

    if-nez v0, :cond_0

    const/4 p1, 0x0

    return p1

    :cond_0
    iget-object p1, p1, Landroidx/appcompat/view/menu/cd;->m:Landroidx/appcompat/view/menu/jh;

    instance-of v0, p1, Landroidx/appcompat/view/menu/cd;

    if-eqz v0, :cond_1

    check-cast p1, Landroidx/appcompat/view/menu/cd;

    goto :goto_0

    :cond_1
    const-string v0, "null cannot be cast to non-null type kotlin.coroutines.CoroutineContext.Element"

    invoke-static {p1, v0}, Landroidx/appcompat/view/menu/x50;->c(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast p1, Landroidx/appcompat/view/menu/jh$b;

    invoke-virtual {p0, p1}, Landroidx/appcompat/view/menu/cd;->b(Landroidx/appcompat/view/menu/jh$b;)Z

    move-result p1

    return p1
.end method

.method public final g()I
    .locals 3

    const/4 v0, 0x2

    move-object v1, p0

    :goto_0
    iget-object v1, v1, Landroidx/appcompat/view/menu/cd;->m:Landroidx/appcompat/view/menu/jh;

    instance-of v2, v1, Landroidx/appcompat/view/menu/cd;

    if-eqz v2, :cond_0

    check-cast v1, Landroidx/appcompat/view/menu/cd;

    goto :goto_1

    :cond_0
    const/4 v1, 0x0

    :goto_1
    if-nez v1, :cond_1

    return v0

    :cond_1
    add-int/lit8 v0, v0, 0x1

    goto :goto_0
.end method

.method public hashCode()I
    .locals 2

    iget-object v0, p0, Landroidx/appcompat/view/menu/cd;->m:Landroidx/appcompat/view/menu/jh;

    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    move-result v0

    iget-object v1, p0, Landroidx/appcompat/view/menu/cd;->n:Landroidx/appcompat/view/menu/jh$b;

    invoke-virtual {v1}, Ljava/lang/Object;->hashCode()I

    move-result v1

    add-int/2addr v0, v1

    return v0
.end method

.method public j(Landroidx/appcompat/view/menu/jh$c;)Landroidx/appcompat/view/menu/jh;
    .locals 2

    const-string v0, "key"

    invoke-static {p1, v0}, Landroidx/appcompat/view/menu/x50;->e(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Landroidx/appcompat/view/menu/cd;->n:Landroidx/appcompat/view/menu/jh$b;

    invoke-interface {v0, p1}, Landroidx/appcompat/view/menu/jh$b;->d(Landroidx/appcompat/view/menu/jh$c;)Landroidx/appcompat/view/menu/jh$b;

    move-result-object v0

    if-eqz v0, :cond_0

    iget-object p1, p0, Landroidx/appcompat/view/menu/cd;->m:Landroidx/appcompat/view/menu/jh;

    return-object p1

    :cond_0
    iget-object v0, p0, Landroidx/appcompat/view/menu/cd;->m:Landroidx/appcompat/view/menu/jh;

    invoke-interface {v0, p1}, Landroidx/appcompat/view/menu/jh;->j(Landroidx/appcompat/view/menu/jh$c;)Landroidx/appcompat/view/menu/jh;

    move-result-object p1

    iget-object v0, p0, Landroidx/appcompat/view/menu/cd;->m:Landroidx/appcompat/view/menu/jh;

    if-ne p1, v0, :cond_1

    move-object p1, p0

    goto :goto_0

    :cond_1
    sget-object v0, Landroidx/appcompat/view/menu/ao;->m:Landroidx/appcompat/view/menu/ao;

    if-ne p1, v0, :cond_2

    iget-object p1, p0, Landroidx/appcompat/view/menu/cd;->n:Landroidx/appcompat/view/menu/jh$b;

    goto :goto_0

    :cond_2
    new-instance v0, Landroidx/appcompat/view/menu/cd;

    iget-object v1, p0, Landroidx/appcompat/view/menu/cd;->n:Landroidx/appcompat/view/menu/jh$b;

    invoke-direct {v0, p1, v1}, Landroidx/appcompat/view/menu/cd;-><init>(Landroidx/appcompat/view/menu/jh;Landroidx/appcompat/view/menu/jh$b;)V

    move-object p1, v0

    :goto_0
    return-object p1
.end method

.method public o(Landroidx/appcompat/view/menu/jh;)Landroidx/appcompat/view/menu/jh;
    .locals 0

    invoke-static {p0, p1}, Landroidx/appcompat/view/menu/jh$a;->a(Landroidx/appcompat/view/menu/jh;Landroidx/appcompat/view/menu/jh;)Landroidx/appcompat/view/menu/jh;

    move-result-object p1

    return-object p1
.end method

.method public p(Ljava/lang/Object;Landroidx/appcompat/view/menu/xw;)Ljava/lang/Object;
    .locals 1

    const-string v0, "operation"

    invoke-static {p2, v0}, Landroidx/appcompat/view/menu/x50;->e(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Landroidx/appcompat/view/menu/cd;->m:Landroidx/appcompat/view/menu/jh;

    invoke-interface {v0, p1, p2}, Landroidx/appcompat/view/menu/jh;->p(Ljava/lang/Object;Landroidx/appcompat/view/menu/xw;)Ljava/lang/Object;

    move-result-object p1

    iget-object v0, p0, Landroidx/appcompat/view/menu/cd;->n:Landroidx/appcompat/view/menu/jh$b;

    invoke-interface {p2, p1, v0}, Landroidx/appcompat/view/menu/xw;->h(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public toString()Ljava/lang/String;
    .locals 3

    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    const/16 v1, 0x5b

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    const-string v1, ""

    sget-object v2, Landroidx/appcompat/view/menu/cd$a;->n:Landroidx/appcompat/view/menu/cd$a;

    invoke-virtual {p0, v1, v2}, Landroidx/appcompat/view/menu/cd;->p(Ljava/lang/Object;Landroidx/appcompat/view/menu/xw;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/String;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const/16 v1, 0x5d

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
