.class public final Landroidx/appcompat/view/menu/ak0$b;
.super Landroidx/appcompat/view/menu/d80;
.source "SourceFile"

# interfaces
.implements Landroidx/appcompat/view/menu/jw;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Landroidx/appcompat/view/menu/ak0;->a(Landroidx/appcompat/view/menu/ck0;Landroidx/appcompat/view/menu/hw;Landroidx/appcompat/view/menu/wg;)Ljava/lang/Object;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = null
.end annotation


# instance fields
.field public final synthetic n:Landroidx/appcompat/view/menu/w9;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/w9;)V
    .locals 0

    iput-object p1, p0, Landroidx/appcompat/view/menu/ak0$b;->n:Landroidx/appcompat/view/menu/w9;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Landroidx/appcompat/view/menu/d80;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Throwable;)V
    .locals 1

    iget-object p1, p0, Landroidx/appcompat/view/menu/ak0$b;->n:Landroidx/appcompat/view/menu/w9;

    sget-object v0, Landroidx/appcompat/view/menu/jp0;->m:Landroidx/appcompat/view/menu/jp0$a;

    sget-object v0, Landroidx/appcompat/view/menu/n31;->a:Landroidx/appcompat/view/menu/n31;

    invoke-static {v0}, Landroidx/appcompat/view/menu/jp0;->a(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    invoke-interface {p1, v0}, Landroidx/appcompat/view/menu/wg;->n(Ljava/lang/Object;)V

    return-void
.end method

.method public bridge synthetic i(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Ljava/lang/Throwable;

    invoke-virtual {p0, p1}, Landroidx/appcompat/view/menu/ak0$b;->a(Ljava/lang/Throwable;)V

    sget-object p1, Landroidx/appcompat/view/menu/n31;->a:Landroidx/appcompat/view/menu/n31;

    return-object p1
.end method
