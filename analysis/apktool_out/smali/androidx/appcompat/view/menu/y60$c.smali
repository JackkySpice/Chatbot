.class public final Landroidx/appcompat/view/menu/y60$c;
.super Landroidx/appcompat/view/menu/y90$a;
.source "SourceFile"


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Landroidx/appcompat/view/menu/y60;->G(Ljava/lang/Object;Landroidx/appcompat/view/menu/ve0;Landroidx/appcompat/view/menu/w60;)Z
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = null
.end annotation


# instance fields
.field public final synthetic d:Landroidx/appcompat/view/menu/y60;

.field public final synthetic e:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/y90;Landroidx/appcompat/view/menu/y60;Ljava/lang/Object;)V
    .locals 0

    iput-object p2, p0, Landroidx/appcompat/view/menu/y60$c;->d:Landroidx/appcompat/view/menu/y60;

    iput-object p3, p0, Landroidx/appcompat/view/menu/y60$c;->e:Ljava/lang/Object;

    invoke-direct {p0, p1}, Landroidx/appcompat/view/menu/y90$a;-><init>(Landroidx/appcompat/view/menu/y90;)V

    return-void
.end method


# virtual methods
.method public bridge synthetic d(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Landroidx/appcompat/view/menu/y90;

    invoke-virtual {p0, p1}, Landroidx/appcompat/view/menu/y60$c;->f(Landroidx/appcompat/view/menu/y90;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public f(Landroidx/appcompat/view/menu/y90;)Ljava/lang/Object;
    .locals 1

    iget-object p1, p0, Landroidx/appcompat/view/menu/y60$c;->d:Landroidx/appcompat/view/menu/y60;

    invoke-virtual {p1}, Landroidx/appcompat/view/menu/y60;->c0()Ljava/lang/Object;

    move-result-object p1

    iget-object v0, p0, Landroidx/appcompat/view/menu/y60$c;->e:Ljava/lang/Object;

    if-ne p1, v0, :cond_0

    const/4 p1, 0x0

    goto :goto_0

    :cond_0
    invoke-static {}, Landroidx/appcompat/view/menu/x90;->a()Ljava/lang/Object;

    move-result-object p1

    :goto_0
    return-object p1
.end method
