.class public final Landroidx/appcompat/view/menu/jg0$a;
.super Landroidx/appcompat/view/menu/d80;
.source "SourceFile"

# interfaces
.implements Landroidx/appcompat/view/menu/jw;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Landroidx/appcompat/view/menu/jg0;->a(Landroidx/appcompat/view/menu/jw;Ljava/lang/Object;Landroidx/appcompat/view/menu/jh;)Landroidx/appcompat/view/menu/jw;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = null
.end annotation


# instance fields
.field public final synthetic n:Landroidx/appcompat/view/menu/jw;

.field public final synthetic o:Ljava/lang/Object;

.field public final synthetic p:Landroidx/appcompat/view/menu/jh;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/jw;Ljava/lang/Object;Landroidx/appcompat/view/menu/jh;)V
    .locals 0

    iput-object p1, p0, Landroidx/appcompat/view/menu/jg0$a;->n:Landroidx/appcompat/view/menu/jw;

    iput-object p2, p0, Landroidx/appcompat/view/menu/jg0$a;->o:Ljava/lang/Object;

    iput-object p3, p0, Landroidx/appcompat/view/menu/jg0$a;->p:Landroidx/appcompat/view/menu/jh;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Landroidx/appcompat/view/menu/d80;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Throwable;)V
    .locals 2

    iget-object p1, p0, Landroidx/appcompat/view/menu/jg0$a;->n:Landroidx/appcompat/view/menu/jw;

    iget-object v0, p0, Landroidx/appcompat/view/menu/jg0$a;->o:Ljava/lang/Object;

    iget-object v1, p0, Landroidx/appcompat/view/menu/jg0$a;->p:Landroidx/appcompat/view/menu/jh;

    invoke-static {p1, v0, v1}, Landroidx/appcompat/view/menu/jg0;->b(Landroidx/appcompat/view/menu/jw;Ljava/lang/Object;Landroidx/appcompat/view/menu/jh;)V

    return-void
.end method

.method public bridge synthetic i(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Ljava/lang/Throwable;

    invoke-virtual {p0, p1}, Landroidx/appcompat/view/menu/jg0$a;->a(Ljava/lang/Throwable;)V

    sget-object p1, Landroidx/appcompat/view/menu/n31;->a:Landroidx/appcompat/view/menu/n31;

    return-object p1
.end method
