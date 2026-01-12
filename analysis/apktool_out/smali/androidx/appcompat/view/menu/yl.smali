.class public Landroidx/appcompat/view/menu/yl;
.super Landroidx/appcompat/view/menu/ml;
.source "SourceFile"


# instance fields
.field public m:I


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/u71;)V
    .locals 0

    invoke-direct {p0, p1}, Landroidx/appcompat/view/menu/ml;-><init>(Landroidx/appcompat/view/menu/u71;)V

    instance-of p1, p1, Landroidx/appcompat/view/menu/lz;

    if-eqz p1, :cond_0

    sget-object p1, Landroidx/appcompat/view/menu/ml$a;->n:Landroidx/appcompat/view/menu/ml$a;

    iput-object p1, p0, Landroidx/appcompat/view/menu/ml;->e:Landroidx/appcompat/view/menu/ml$a;

    goto :goto_0

    :cond_0
    sget-object p1, Landroidx/appcompat/view/menu/ml$a;->o:Landroidx/appcompat/view/menu/ml$a;

    iput-object p1, p0, Landroidx/appcompat/view/menu/ml;->e:Landroidx/appcompat/view/menu/ml$a;

    :goto_0
    return-void
.end method


# virtual methods
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
