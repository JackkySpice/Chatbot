.class public final synthetic Landroidx/appcompat/view/menu/kq0;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroidx/appcompat/view/menu/ar0$d;


# instance fields
.field public final synthetic a:Landroidx/appcompat/view/menu/cs0;


# direct methods
.method public synthetic constructor <init>(Landroidx/appcompat/view/menu/cs0;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Landroidx/appcompat/view/menu/kq0;->a:Landroidx/appcompat/view/menu/cs0;

    return-void
.end method


# virtual methods
.method public final a()Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/kq0;->a:Landroidx/appcompat/view/menu/cs0;

    invoke-virtual {v0}, Landroid/database/sqlite/SQLiteOpenHelper;->getWritableDatabase()Landroid/database/sqlite/SQLiteDatabase;

    move-result-object v0

    return-object v0
.end method
