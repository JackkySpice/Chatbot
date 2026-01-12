.class public Landroidx/appcompat/view/menu/ml;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroidx/appcompat/view/menu/il;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Landroidx/appcompat/view/menu/ml$a;
    }
.end annotation


# instance fields
.field public a:Landroidx/appcompat/view/menu/il;

.field public b:Z

.field public c:Z

.field public d:Landroidx/appcompat/view/menu/u71;

.field public e:Landroidx/appcompat/view/menu/ml$a;

.field public f:I

.field public g:I

.field public h:I

.field public i:Landroidx/appcompat/view/menu/yl;

.field public j:Z

.field public k:Ljava/util/List;

.field public l:Ljava/util/List;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/u71;)V
    .locals 3

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x0

    iput-object v0, p0, Landroidx/appcompat/view/menu/ml;->a:Landroidx/appcompat/view/menu/il;

    const/4 v1, 0x0

    iput-boolean v1, p0, Landroidx/appcompat/view/menu/ml;->b:Z

    iput-boolean v1, p0, Landroidx/appcompat/view/menu/ml;->c:Z

    sget-object v2, Landroidx/appcompat/view/menu/ml$a;->m:Landroidx/appcompat/view/menu/ml$a;

    iput-object v2, p0, Landroidx/appcompat/view/menu/ml;->e:Landroidx/appcompat/view/menu/ml$a;

    const/4 v2, 0x1

    iput v2, p0, Landroidx/appcompat/view/menu/ml;->h:I

    iput-object v0, p0, Landroidx/appcompat/view/menu/ml;->i:Landroidx/appcompat/view/menu/yl;

    iput-boolean v1, p0, Landroidx/appcompat/view/menu/ml;->j:Z

    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Landroidx/appcompat/view/menu/ml;->k:Ljava/util/List;

    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Landroidx/appcompat/view/menu/ml;->l:Ljava/util/List;

    iput-object p1, p0, Landroidx/appcompat/view/menu/ml;->d:Landroidx/appcompat/view/menu/u71;

    return-void
.end method


# virtual methods
.method public a(Landroidx/appcompat/view/menu/il;)V
    .locals 5

    iget-object p1, p0, Landroidx/appcompat/view/menu/ml;->l:Ljava/util/List;

    invoke-interface {p1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :cond_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_1

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Landroidx/appcompat/view/menu/ml;

    iget-boolean v0, v0, Landroidx/appcompat/view/menu/ml;->j:Z

    if-nez v0, :cond_0

    return-void

    :cond_1
    const/4 p1, 0x1

    iput-boolean p1, p0, Landroidx/appcompat/view/menu/ml;->c:Z

    iget-object v0, p0, Landroidx/appcompat/view/menu/ml;->a:Landroidx/appcompat/view/menu/il;

    if-eqz v0, :cond_2

    invoke-interface {v0, p0}, Landroidx/appcompat/view/menu/il;->a(Landroidx/appcompat/view/menu/il;)V

    :cond_2
    iget-boolean v0, p0, Landroidx/appcompat/view/menu/ml;->b:Z

    if-eqz v0, :cond_3

    iget-object p1, p0, Landroidx/appcompat/view/menu/ml;->d:Landroidx/appcompat/view/menu/u71;

    invoke-virtual {p1, p0}, Landroidx/appcompat/view/menu/u71;->a(Landroidx/appcompat/view/menu/il;)V

    return-void

    :cond_3
    iget-object v0, p0, Landroidx/appcompat/view/menu/ml;->l:Ljava/util/List;

    invoke-interface {v0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object v0

    const/4 v1, 0x0

    const/4 v2, 0x0

    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_5

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Landroidx/appcompat/view/menu/ml;

    instance-of v4, v3, Landroidx/appcompat/view/menu/yl;

    if-eqz v4, :cond_4

    goto :goto_0

    :cond_4
    add-int/lit8 v2, v2, 0x1

    move-object v1, v3

    goto :goto_0

    :cond_5
    if-eqz v1, :cond_8

    if-ne v2, p1, :cond_8

    iget-boolean p1, v1, Landroidx/appcompat/view/menu/ml;->j:Z

    if-eqz p1, :cond_8

    iget-object p1, p0, Landroidx/appcompat/view/menu/ml;->i:Landroidx/appcompat/view/menu/yl;

    if-eqz p1, :cond_7

    iget-boolean v0, p1, Landroidx/appcompat/view/menu/ml;->j:Z

    if-eqz v0, :cond_6

    iget v0, p0, Landroidx/appcompat/view/menu/ml;->h:I

    iget p1, p1, Landroidx/appcompat/view/menu/ml;->g:I

    mul-int/2addr v0, p1

    iput v0, p0, Landroidx/appcompat/view/menu/ml;->f:I

    goto :goto_1

    :cond_6
    return-void

    :cond_7
    :goto_1
    iget p1, v1, Landroidx/appcompat/view/menu/ml;->g:I

    iget v0, p0, Landroidx/appcompat/view/menu/ml;->f:I

    add-int/2addr p1, v0

    invoke-virtual {p0, p1}, Landroidx/appcompat/view/menu/ml;->d(I)V

    :cond_8
    iget-object p1, p0, Landroidx/appcompat/view/menu/ml;->a:Landroidx/appcompat/view/menu/il;

    if-eqz p1, :cond_9

    invoke-interface {p1, p0}, Landroidx/appcompat/view/menu/il;->a(Landroidx/appcompat/view/menu/il;)V

    :cond_9
    return-void
.end method

.method public b(Landroidx/appcompat/view/menu/il;)V
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/ml;->k:Ljava/util/List;

    invoke-interface {v0, p1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    iget-boolean v0, p0, Landroidx/appcompat/view/menu/ml;->j:Z

    if-eqz v0, :cond_0

    invoke-interface {p1, p1}, Landroidx/appcompat/view/menu/il;->a(Landroidx/appcompat/view/menu/il;)V

    :cond_0
    return-void
.end method

.method public c()V
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/ml;->l:Ljava/util/List;

    invoke-interface {v0}, Ljava/util/List;->clear()V

    iget-object v0, p0, Landroidx/appcompat/view/menu/ml;->k:Ljava/util/List;

    invoke-interface {v0}, Ljava/util/List;->clear()V

    const/4 v0, 0x0

    iput-boolean v0, p0, Landroidx/appcompat/view/menu/ml;->j:Z

    iput v0, p0, Landroidx/appcompat/view/menu/ml;->g:I

    iput-boolean v0, p0, Landroidx/appcompat/view/menu/ml;->c:Z

    iput-boolean v0, p0, Landroidx/appcompat/view/menu/ml;->b:Z

    return-void
.end method

.method public d(I)V
    .locals 1

    iget-boolean v0, p0, Landroidx/appcompat/view/menu/ml;->j:Z

    if-eqz v0, :cond_0

    return-void

    :cond_0
    const/4 v0, 0x1

    iput-boolean v0, p0, Landroidx/appcompat/view/menu/ml;->j:Z

    iput p1, p0, Landroidx/appcompat/view/menu/ml;->g:I

    iget-object p1, p0, Landroidx/appcompat/view/menu/ml;->k:Ljava/util/List;

    invoke-interface {p1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_1

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Landroidx/appcompat/view/menu/il;

    invoke-interface {v0, v0}, Landroidx/appcompat/view/menu/il;->a(Landroidx/appcompat/view/menu/il;)V

    goto :goto_0

    :cond_1
    return-void
.end method

.method public toString()Ljava/lang/String;
    .locals 2

    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    iget-object v1, p0, Landroidx/appcompat/view/menu/ml;->d:Landroidx/appcompat/view/menu/u71;

    iget-object v1, v1, Landroidx/appcompat/view/menu/u71;->b:Landroidx/appcompat/view/menu/lf;

    invoke-virtual {v1}, Landroidx/appcompat/view/menu/lf;->r()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v1, ":"

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v1, p0, Landroidx/appcompat/view/menu/ml;->e:Landroidx/appcompat/view/menu/ml$a;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v1, "("

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-boolean v1, p0, Landroidx/appcompat/view/menu/ml;->j:Z

    if-eqz v1, :cond_0

    iget v1, p0, Landroidx/appcompat/view/menu/ml;->g:I

    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v1

    goto :goto_0

    :cond_0
    const-string v1, "unresolved"

    :goto_0
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v1, ") <t="

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v1, p0, Landroidx/appcompat/view/menu/ml;->l:Ljava/util/List;

    invoke-interface {v1}, Ljava/util/List;->size()I

    move-result v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string v1, ":d="

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v1, p0, Landroidx/appcompat/view/menu/ml;->k:Ljava/util/List;

    invoke-interface {v1}, Ljava/util/List;->size()I

    move-result v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string v1, ">"

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
